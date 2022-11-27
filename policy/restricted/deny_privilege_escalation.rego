package main

import data.lib.k8s

deny_privilege_escalation[msg] {
	container := k8s.containers(input)[_]
	not container.securityContext.allowPrivilegeEscalation == false
	msg := sprintf("container %s in %s/%s allows privilege escalation", [container.name, input.kind, input.metadata.name])
}
