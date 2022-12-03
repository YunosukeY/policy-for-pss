package lib.restricted

import data.lib.k8s
import data.lib.wrapper
import future.keywords

violation_privilege_escalation contains msg if {
	resource := wrapper.resource(input)

	not resource.metadata.labels.allowPrivilegeEscalation

	pod := k8s.pod(resource)
	not pod.spec.os.name == "windows"

	some container in k8s.containers(resource)
	not container.securityContext.allowPrivilegeEscalation == false

	msg := wrapper.format("restricted level: container %s in %s/%s allows privilege escalation", [container.name, resource.kind, resource.metadata.name])
}
