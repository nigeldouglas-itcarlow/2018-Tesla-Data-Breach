# 2018 Tesla Data Breach
As part of this task I was required to map the Tesla Data Breach to the MITRE ATT&amp;CK framework. From here I select any <b>2 specific ‘techniques’</b> from the incident and replicate both on a ‘proof of concept’ basis. This will allow me to display my understanding by synthesizing the selected technical techniques. I'll document 2 techniques in this repo.

# Architectural Diagram

![outline](https://github.com/nigeldouglas-itcarlow/2018-Tesla-Data-Breach/assets/126002808/e8913e81-8178-4f98-8474-0243b32fc098)
[Link to Google Diagram](https://docs.google.com/drawings/d/1Vx_12imsuZ7a-8dCVp3JT9yXyzVF4ETjX4Hb5ecpLPw/edit)

## Scripts

All mining code operations are sourced from my other repo: <br/>
https://github.com/n1g3ld0ugla5/falco-mining-demo

## Setting-up the Sanbox

Had to setup an ```AWS-CLI Profile``` in order to interact with AWS services via my local workstation
```
aws configure --profile nigel-aws-profile
export AWS_PROFILE=nigel-aws-profile                                            
aws sts get-caller-identity --profile nigel-aws-profile
aws eks update-kubeconfig --region eu-west-1 --name tesla-cluster
```

![Screenshot 2023-10-20 at 17 04 05](https://github.com/nigeldouglas-itcarlow/2018-Tesla-Data-Breach/assets/126002808/6c24b473-2f72-4707-a58b-4296e704ccce)

Once I had AWS-CLI installed, I created a ```1 node, AWS EKS cluster``` using EKSCTL CLI tool. <br/>
Notice how I use the ```date``` command purely to confirm when those actions were enforced.

```
date
eksctl create cluster tesla-cluster --node-type t3.xlarge --nodes=1 --nodes-min=0 --nodes-max=3 --max-pods-per-node 58
```

![Screenshot 2023-10-20 at 17 08 09](https://github.com/nigeldouglas-itcarlow/2018-Tesla-Data-Breach/assets/126002808/85425963-6ef6-4677-9177-87e548b2e980)

Once the cluster is successfully spun-up, I can scale it down to ```zero nodes``` to bring my compute costs in the cloud down to $0 until I'm ready to do actual work.

```
date
eksctl get cluster
eksctl get nodegroup --cluster tesla-cluster
eksctl scale nodegroup --cluster tesla-cluster --name ng-a4f7283a --nodes 0
```

![Screenshot 2023-10-20 at 18 01 38](https://github.com/nigeldouglas-itcarlow/2018-Tesla-Data-Breach/assets/126002808/7826f6ed-1947-4b23-93d7-53d83f2ca62b)

## Exposing an insecure Kubernetes Dashboard

[Kubernetes Dashboard](https://github.com/kubernetes/dashboard/tree/master) is a general purpose, web-based UI for Kubernetes clusters. <br/>
It allows users to manage applications running in the cluster and troubleshoot them, as well as manage the cluster itself.<br/>
<br/>
When Kubernetes dashboard is installed using the recommended settings, both ```authentication``` and ```HTTPS``` are enabled. Sometimes, organizations like Tesla choose to disable authentication or HTTPS. <br/>
<br/>
For example, if Kubernetes dashboard is served behind a proxy, then it's unnecessary to enable authentication when the proxy has its own authentication enabled. <br/>
<br/>
Kubernetes dashboard uses auto-generated certificates for HTTPS, which may cause problems for HTTP client to access. <br/>
The below ```YAML``` manifest is pre-packaged to provide an insecure dashboard with disable authentication and disabled HTTP/s.
```
kubectl apply -f https://vividcode.io/content/insecure-kubernetes-dashboard.yml
```

The above manifest is a modified version of the deployment of Kubernetes dashboard which has removed the argument ```--auto-generate-certificates``` and has added some extra arguments:

```--enable-skip-login``` <br/>
```--disable-settings-authorizer``` <br/>
```--enable-insecure-login``` <br/>
```--insecure-bind-address=0.0.0.0``` <br/>

<img width="1439" alt="Screenshot 2023-10-21 at 12 41 45" src="https://github.com/nigeldouglas-itcarlow/2018-Tesla-Data-Breach/assets/126002808/e2e3ec87-52fc-4799-aec8-c2e733d1e490">


After this change, Kubernetes dashboard server now starts on ```port 9090 for HTTP```. 
It has also modified the ```livenessProbe``` to use HTTP as the scheme and 9090 as the port. <br/>

<b> INSERT SCREENSHOT OF SERVICES AND DEPLOYMENTS AFTER CREATION </b>

Port 9090 is added as the ```containerPort```. <br/>
Similarly, the Kubernetes Service abstraction for the dashboard opens port 80 and uses ```9090 as the target port```. <br/>
<br/>
After you have done this, when Kubernetes dashboard is opened, you can click ```Skip``` in the login page to skip authentication and go to the dashboard directly.

<img width="883" alt="kubernetes_dashboard_skip" src="https://github.com/nigeldouglas-itcarlow/2018-Tesla-Data-Breach/assets/126002808/ba26d2c0-304e-49d7-86d9-64b8a368b05e">

#### Supporting documentation for Kubernetes Dashboard without Authentication

- [Kubernetes Web UI Activation without Authentication](https://medium.com/@sarpkoksal/kubernetes-web-ui-dashboard-activation-without-authentication-e99447c8a71d)
- [Skipping login to allows users to have unrestricted access](https://github.com/kubernetes/dashboard/issues/2412)
- [Bypassing authentication for the local Kubernetes Cluster Dashboard](https://devblogs.microsoft.com/premier-developer/bypassing-authentication-for-the-local-kubernetes-cluster-dashboard/)

## Installing Falco as our SOC solution


#### Supporting documentation for Falco event collect from Kubernetes and Cloud

- [Kubernetes Audit Logs](https://falco.org/docs/event-sources/plugins/kubernetes-audit/)
- [K8s Audit for EKS Logs](https://falco.org/blog/k8saudit-eks-plugin/)
- [Falco on AWS Cloud](https://falco.org/blog/falco-on-aws/)

## Enabling Kubernetes Audit Logs in Falco
To enable Kubernetes audit logs, you need to change the arguments to the ```kube-apiserver``` process to add ```--audit-policy-file``` and ```--audit-webhook-config-file``` arguments and provide files that implement an audit policy/webhook configuration.
<br/><br/>
Below is a step-by-step guide will show you how to configure kubernetes audit logs on minikube and deploy Falco. <br/>
Managed Kubernetes providers, like AWS EKS, usually provide a mechanism to configure the audit system.<br/>
https://falco.org/docs/install-operate/third-party/learning/
