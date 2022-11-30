package lib.baseline

import data.lib.k8s
import future.keywords

deny_unmasked_proc_mount contains msg if {
	container := k8s.containers(input)[_]
	container.securityContext.procMount != "Default"
	msg := sprintf("container %s in %s/%s doesn't mask /proc mount", [container.name, input.kind, input.metadata.name])
}
