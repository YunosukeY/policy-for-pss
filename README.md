# Conftest Policies for Pod Security Standards

[![Conftest](https://github.com/YunosukeY/policies-for-pss/actions/workflows/ci.yaml/badge.svg?branch=master&event=push)](https://github.com/YunosukeY/policies-for-pss/actions/workflows/ci.yaml)
![Coverage](https://img.shields.io/endpoint?url=https://gist.githubusercontent.com/YunosukeY/0c2e618c502912eff6e83e26b24e5c82/raw/opa-coverage-badge.json)

Implementing Pod Security Standards as Conftest Policy.

[Pod Security Standards | Kubernetes](https://kubernetes.io/docs/concepts/security/pod-security-standards/)

## Features

If you want to allow violations for specific resources, you can use `allowXxx` labels.

| Label name                 | Description             |
| -------------------------- | ----------------------- |
| `allowHostProcess`         |                         |
| `allowHostNamespace`       |                         |
| `allowPrivileged`          |                         |
|                            |                         |
| `allowHostPath`            | allows hostPath volumes |
| `allowHostPort`            | allows host ports       |
|                            |                         |
|                            |                         |
|                            |                         |
|                            |                         |
| `allowAllSysctls`          |                         |
|                            |                         |
| `allowPrivilegeEscalation` |                         |
| `allowRunAsRoot`           |                         |
| `allowRunAsRootUser`       |                         |
|                            |                         |
|                            |                         |

### Examples
