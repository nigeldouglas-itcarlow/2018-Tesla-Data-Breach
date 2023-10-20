# 2018 Tesla Data Breach
As part of this task I was required to map the Tesla Data Breach to the MITRE ATT&amp;CK framework. From here I select any <b>2 specific ‘techniques’</b> from the incident and replicate both on a ‘proof of concept’ basis. This will allow me to display my understanding by synthesizing the selected technical techniques. I'll document 2 techniques in this repo.

# Architectural Diagram

![outline](https://github.com/nigeldouglas-itcarlow/2018-Tesla-Data-Breach/assets/126002808/e8913e81-8178-4f98-8474-0243b32fc098)

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
