package lib.restricted

import data.lib.k8s
import future.keywords

deny_privilege_escalation contains msg if {
	not input.metadata.labels.allowPrivilegeEscalation
	some container in k8s.containers(input)
	not container.securityContext.allowPrivilegeEscalation == false
	msg := sprintf("container %s in %s/%s allows privilege escalation", [container.name, input.kind, input.metadata.name])
}
