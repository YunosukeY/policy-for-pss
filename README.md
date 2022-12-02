# Conftest Policies for Pod Security Standards

[![ci](https://github.com/YunosukeY/policies-for-pss/actions/workflows/ci.yaml/badge.svg?branch=master&event=push)](https://github.com/YunosukeY/policies-for-pss/actions/workflows/ci.yaml)
![Coverage](https://img.shields.io/endpoint?url=https://gist.githubusercontent.com/YunosukeY/0c2e618c502912eff6e83e26b24e5c82/raw/opa-coverage-badge.json)

Implementing Pod Security Standards as Conftest Policy.

[Pod Security Standards | Kubernetes](https://kubernetes.io/docs/concepts/security/pod-security-standards/)

## Examples

With an unsafe manifest

```sh
$ conftest test example/unsafe.yaml
FAIL - example/unsafe.yaml - main - container nginx in Deployment/nginx-deployment allows privilege escalation
FAIL - example/unsafe.yaml - main - container nginx in Deployment/nginx-deployment doesn't drop "ALL" capability
FAIL - example/unsafe.yaml - main - container nginx in Deployment/nginx-deployment must be set seccomp profile
FAIL - example/unsafe.yaml - main - container nginx in Deployment/nginx-deployment runs as root
FAIL - example/unsafe.yaml - main - pod in Deployment/nginx-deployment must be set seccomp profile
FAIL - example/unsafe.yaml - main - pod in Deployment/nginx-deployment runs as root

17 tests, 11 passed, 0 warnings, 6 failures, 0 exceptions
```

With a safe manifest

```sh
$ conftest test example/safe.yaml

17 tests, 17 passed, 0 warnings, 0 failures, 0 exceptions
```

## Usage

```sh
$ conftest test --update https://raw.githubusercontent.com/YunosukeY/policies-for-pss/master/policy/deny.rego <file-to-test>
```

## Features

If you want to allow violations for specific resources, you can use `allowXxx` labels.

For baseline

- `allowHostProcess`
- `allowHostNamespace`
- `allowPrivileged`
- `allowPrivilegedLevelCapabilities`
- `allowHostPath`
- `allowHostPort`
- `allowAllAppArmorProfile`
- `allowAllSeLinuxOptions`
- `allowUnmaskedProcMount`
- `allowPrivilegedLevelSeccompTypes`
- `allowAllSysctls`

For restricted

- `allowAllVolumeTypes`
- `allowPrivilegeEscalation`
- `allowRunAsRoot`
- `allowRunAsRootUser`
- `allowBaselineLevelSeccompTypes`
- `allowBaselineLevelCapabilities`

### Examples

```sh
$ cat example/allowed.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: nginx-deployment
  labels:
    allowPrivilegeEscalation: true
    allowRunAsRoot: true
    allowBaselineLevelSeccompTypes: true
    allowBaselineLevelCapabilities: true
spec:
  selector:
    matchLabels:
      app: nginx
  template:
    metadata:
      labels:
        app: nginx
    spec:
      containers:
        - name: nginx
          image: nginx:1.14.2
```

```sh
$ conftest test example/allowed.yaml

17 tests, 17 passed, 0 warnings, 0 failures, 0 exceptions
```
