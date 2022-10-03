# Amazon EKS Security Checklist

## Container Image Security

* Use a minimal base image such as [scratch](https://hub.docker.com/_/scratch) and [distroless](https://github.com/GoogleContainerTools/distroless)
    * Eliminate binaries that are not needed at runtime: Docker multi-stage builds make using distroless images easy
    * Remove access to container’s shell environment
    * Reduce container attack-surface area with purpose-built images
    * Reduce the number of layers in an image
* Containers should have a single-concern, and be self-contained
* Lint your Dockerfiles 
* Perform static analysis of code (SAST), Ideally integrated into CI/CD pipeline before container image is created
* Scan container images for vulnerabilities, Ideally integrated into CI/CD pipeline before pushing images to a repository
* No sensitive data within the image, Mount secrets in memory at runtime.
* Sign container images (Amazon ECR does not support yet. Sep 2022) 

## Amazon Elastic Container Registry (ECR)

* Tag immutability
* Image scanning 
* Lifecycle management of images using policies
e.g. Filtering on image age - find more [here](https://docs.aws.amazon.com/AmazonECR/latest/userguide/lifecycle_policy_examples.html). 

```
{
    "rules": [
        {
            "rulePriority": 1,
            "description": "Expire images older than 14 days",
            "selection": {
                "tagStatus": "untagged",
                "countType": "sinceImagePushed",
                "countUnit": "days",
                "countNumber": 14
            },
            "action": {
                "type": "expire"
            }
        }
    ]
}
```

```
{
    "rules": [
        {
            "rulePriority": 1,
            "description": "Keep only one untagged image, expire all others",
            "selection": {
                "tagStatus": "untagged",
                "countType": "imageCountMoreThan",
                "countNumber": 1
            },
            "action": {
                "type": "expire"
            }
        }
    ]
}
```

* Accessible over VPC interface endpoints 
* Access control using IAM policies 

```
{
    "Version": "2012-10-17",
   "Statement": [{
        "Sid": "ECR Repository Policy",
        "Effect": "Allow",
        "Principal": {
            "AWS": "arn:aws:iam::account-id:user/username"
         },
        "Action": [
            "ecr:DescribeImages",
           "ecr:DescribeRepositories"
         ],
        "Resource": [
            "arn:aws:ecr:region:account-id:repository/repository-name"
        ]
    }]
}
```

## Container Runtime Security

* Configure CPU & memory resources for a container
* Deny permission to run as root 
* Deny mounting host path (except for emptyDir option)
* Deny privileged mode execution
* Restrict the use of host networking
* Block access to instance metadata service (IMDS)
    * Find more [here](https://aws.github.io/aws-eks-best-practices/security/docs/iam/#restrict-access-to-the-instance-profile-assigned-to-the-worker-node) how to block access instance metadata.
* Enable [Seccomp](https://en.wikipedia.org/wiki/Seccomp) profile provided by container runtime 
    * Linux kernel feature that restricts programs from making unauthorized system calls
* Enforce security policies using Policy-as-Code (PaC) solutions like [OPA](https://www.openpolicyagent.org/), [Gatekeeper](https://github.com/open-policy-agent/gatekeeper), [Kyverno](https://kyverno.io/)
    * https://github.com/open-policy-agent/gatekeeper-library/tree/master/mutation/pod-security-policy
    * https://github.com/open-policy-agent/gatekeeper-library/blob/master/library/general/allowedrepos/template.yaml
    * https://github.com/aws/aws-eks-best-practices/tree/master/policies/opa/gatekeeper/constraints

## Container Host
* Use an OS that is purpose-built and optimized to run containers
    * ECS/EKS-optimized AMIs, Bottlerocket AMI
* Deploy worker nodes on private subnets
* Automate periodic replacement of worker nodes 
* Minimize and audit host access
    * Consider using Session Manager in AWS SSM
    * Remove SSH access and need for key pairs 
    * Treat worker nodes as immutable
* Periodically verify compliance with [CIS benchmarks for Kubernetes](https://aws.amazon.com/ko/blogs/containers/introducing-cis-amazon-eks-benchmark/) 
    * [What is CIS?](https://cloud.google.com/kubernetes-engine/docs/concepts/cis-benchmarks?hl=ko)

## Identity and Access Management 
* Make the EKS Cluster Endpoint [private](https://aws.amazon.com/ko/blogs/containers/de-mystifying-cluster-networking-for-amazon-eks-worker-nodes/)
    * Public and Private
    ![](/SecurityChecklist/images/public_private_ep.jpg)
    * Private Endpoint only
    ![](/SecurityChecklist/images/private_ep.jpg)
* Create the cluster with a dedicated IAM role
    * When you create an Amazon EKS cluster, the IAM entity user or role, such as a federated user that creates the cluster, is automatically granted system:masters permissions in the cluster's RBAC configuration. This access cannot be removed and is not managed through the aws-auth ConfigMap. Therefore it is a good idea to create the cluster with a dedicated IAM role and regularly audit who can assume this role. This role should not be used to perform routine actions on the cluster, and instead additional users should be granted access to the cluster through the aws-auth ConfigMap for this purpose. After the aws-auth ConfigMap is configured, the role can be deleted and only recreated in an emergency / break glass scenario where the aws-auth ConfigMap is corrupted and the cluster is otherwise inaccessible. This can be particularly useful in production clusters which do not usually have direct user access configured.
* Employ principle of least privileges
* Leverage IRSA (IAM Role for Sevice Account)
    * ![](/SecurityChecklist/images/irsa.jpg)
    * [Update the aws-node daemonset to use IRSA](https://aws.github.io/aws-eks-best-practices/security/docs/iam/#update-the-aws-node-daemonset-to-use-irsa)
        * [Script](https://github.com/aws/aws-eks-best-practices/tree/master/projects/enable-irsa/src)
        * [Refer to AWS Official doc](https://docs.aws.amazon.com/eks/latest/userguide/cni-iam-role.html)


## Kubernetes Security Monitoring
* Analyze Control Plane logs
![](/SecurityChecklist/images/controlplane_log.jpg)
* Audit EKS API calls with CloudTrail
![](/SecurityChecklist/images//SecurityChecklist/images/log_analysis.jpg)


## Protect Secrets
* ASCP is a plugin for industry standard Kubernetes Secrets Store CSI Driver: Securely store and manage secrets in Secrets Manager or SSM Parameter Store and Make secrets accessible to Pods running on EKS, mounted into the Pod file system as volume
* Limit and restrict secrets access to specific Pods with IAM policies using IRSA

## Network Security (Pod to Pod Communication)

* Network policies: Implement network segmentation and tenant isolation  
    * https://tigera.awsworkshop.io/
* [Security Groups for Pods](https://docs.aws.amazon.com/eks/latest/userguide/security-groups-for-pods.html)
    * limits!

## Threat Detection using Amazon GuardDuty
![](/SecurityChecklist/images/guardduty.png)

## Multi Tentant SaaS Security
- https://d1.awsstatic.com/whitepapers/security-practices-for-multi-tenant-saas-apps-using-eks.pdf
- https://aws.github.io/aws-eks-best-practices/security/docs/
