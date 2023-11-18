# Conftest Policy for Pod Security Standards

[![opa](https://github.com/YunosukeY/policy-for-pss/actions/workflows/opa.yaml/badge.svg?branch=master&event=push)](https://github.com/YunosukeY/policy-for-pss/actions/workflows/opa.yaml)
![Coverage](https://img.shields.io/endpoint?url=https://gist.githubusercontent.com/YunosukeY/0c2e618c502912eff6e83e26b24e5c82/raw/opa-coverage-badge.json)
[![gator](https://github.com/YunosukeY/policy-for-pss/actions/workflows/gator.yaml/badge.svg?branch=master&event=push)](https://github.com/YunosukeY/policy-for-pss/actions/workflows/gator.yaml)

This repository implements Pod Security Standards as Conftest policy.<br>
It also corresponds to Gatekeeper policy.

## Usage

For Conftest:

```sh
$ conftest test --update https://github.com/YunosukeY/policy-for-pss/raw/1.28/bundle.tar.gz <file-to-test>
```

For Gatekeeper:

```sh
$ kubectl apply -f https://github.com/YunosukeY/policy-for-pss/raw/1.28/k8s/template_PodSecurityStandards.yaml
$ kubectl apply -f https://github.com/YunosukeY/policy-for-pss/raw/1.28/k8s/constraint_PodSecurityStandards.yaml
```

## Features

If you want to allow violations for specific resources, you can use `allowXxx` labels.

For baseline level rules:

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

For restricted level rules:

- `allowAllVolumeTypes`
- `allowPrivilegeEscalation`
- `allowRunAsRoot`
- `allowRunAsRootUser`
- `allowBaselineLevelSeccompTypes`
- `allowBaselineLevelCapabilities`

Example:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: nginx-deployment
  labels:
    allowPrivilegeEscalation: "true"
    allowRunAsRoot: "true"
    allowBaselineLevelSeccompTypes: "true"
    allowBaselineLevelCapabilities: "true"
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
