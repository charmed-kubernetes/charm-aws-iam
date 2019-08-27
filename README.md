# AWS IAM Charm

The AWS IAM charm allows a Kubernetes cluster to be authenticated via the Amazon
API using AWS users and groups. The authorization falls to RBAC, so an Amazon
user or group maps to an RBAC user.

## Usage

The AWS IAM charm is subordinate to the [`kubernetes-master`]
(https://jaas.ai/u/containers/kubernetes-master)
charm and needs to be related to it. It will then set the Kubernetes API server
to authenticate through the AWS IAM pod deployed inside the cluster.

```
juju deploy cs:~containers/aws-iam
juju deploy charmed-kubernetes
juju add-relation aws-iam kubernetes-master
```

## Further information

- [AWS IAM Homepage](https://github.com/kubernetes-sigs/aws-iam-authenticator)
- [AWS IAM Charm Issue Tracker](https://launchpad.net/charm-aws-iam)
- [AWS IAM Issue Tracker](https://github.com/kubernetes-sigs/aws-iam-authenticator/issues)
