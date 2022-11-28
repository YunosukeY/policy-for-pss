package lib.baseline

import data.lib.k8s

deny_privileged[msg] {
	container := k8s.containers(input)[_]
	container.securityContext.privileged
	msg := sprintf("container %s in %s/%s is privileged", [container.name, input.kind, input.metadata.name])
}
