package lib.restricted

import data.lib.k8s
import future.keywords

violation_privilege_escalation contains msg if {
	not input.metadata.labels.allowPrivilegeEscalation

	pod := k8s.pod(input)
	not pod.spec.os.name == "windows"

	some container in k8s.containers(input)
	not container.securityContext.allowPrivilegeEscalation == false
	msg := sprintf("restricted level: container %s in %s/%s allows privilege escalation", [container.name, input.kind, input.metadata.name])
}
