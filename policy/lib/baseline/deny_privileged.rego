package lib.baseline

import data.lib.k8s
import future.keywords

deny_privileged contains msg if {
	not input.metadata.labels.allowPrivileged
	some container in k8s.containers(input)
	container.securityContext.privileged
	msg := sprintf("container %s in %s/%s is privileged", [container.name, input.kind, input.metadata.name])
}
