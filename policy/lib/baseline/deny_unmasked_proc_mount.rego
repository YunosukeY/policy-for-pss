package lib.baseline

import data.lib.k8s

deny_unmasked_proc_mount[msg] {
	container := k8s.containers(input)[_]
	container.securityContext.procMount != "Default"
	msg := sprintf("container %s in %s/%s doesn't mask /proc mount", [container.name, input.kind, input.metadata.name])
}
