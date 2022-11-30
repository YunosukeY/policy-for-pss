package lib.baseline

import data.lib.k8s
import future.keywords

deny_privileged contains msg if {
	container := k8s.containers(input)[_]
	container.securityContext.privileged
	msg := sprintf("container %s in %s/%s is privileged", [container.name, input.kind, input.metadata.name])
}
