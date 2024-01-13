package lib.baseline.privileged

import data.lib.k8s
import data.lib.wrapper
import rego.v1

violation_privileged contains msg if {
	resource := wrapper.resource(input)
	pod := k8s.pod(resource)

	not resource.metadata.labels.allowPrivileged
	not pod.metadata.labels.allowPrivileged

	some container in k8s.containers(resource)
	container.securityContext.privileged

	msg := wrapper.format("baseline level: container %s in %s/%s is privileged", [container.name, resource.kind, resource.metadata.name])
}
