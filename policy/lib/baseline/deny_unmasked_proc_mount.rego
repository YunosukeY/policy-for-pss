package lib.baseline

import data.lib.k8s
import future.keywords

deny_unmasked_proc_mount contains msg if {
	not input.metadata.labels.allowUnmaskedProcMount
	some container in k8s.containers(input)
	container.securityContext.procMount != "Default"
	msg := sprintf("baseline level: container %s in %s/%s doesn't mask /proc mount", [container.name, input.kind, input.metadata.name])
}
