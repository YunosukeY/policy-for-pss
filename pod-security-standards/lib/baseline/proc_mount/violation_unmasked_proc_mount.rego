package lib.baseline.proc_mount

import data.lib.k8s
import data.lib.wrapper
import rego.v1

violation_unmasked_proc_mount contains msg if {
	resource := wrapper.resource(input)
	pod := k8s.pod(resource)

	not resource.metadata.labels.allowUnmaskedProcMount
	not pod.metadata.labels.allowUnmaskedProcMount

	some container in k8s.containers(resource)
	container.securityContext.procMount != "Default"

	msg := wrapper.format("baseline level: container %s in %s/%s doesn't mask /proc mount", [container.name, resource.kind, resource.metadata.name])
}
