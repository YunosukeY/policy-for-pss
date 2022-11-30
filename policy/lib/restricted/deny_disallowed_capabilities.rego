package lib.restricted

import data.lib.k8s
import future.keywords

deny_disallowed_capabilities contains msg if {
	container := k8s.containers(input)[_]
	{c | some c in container.securityContext.capabilities.drop} & {"ALL"} != {"ALL"}
	msg := sprintf("container %s in %s/%s doesn't drop \"ALL\" capability", [container.name, input.kind, input.metadata.name])
}

allowed_capabilities := {"NET_BIND_SERVICE"}

deny_disallowed_capabilities contains msg if {
	p := k8s.pod(input)
	{n | n := p.spec.os.name; n == "windows"} != {"windows"}

	container := k8s.containers(input)[_]
	count({c | some c in container.securityContext.capabilities.add; not c in allowed_capabilities}) != 0
	msg := sprintf("container %s in %s/%s has disallowed capabilities", [container.name, input.kind, input.metadata.name])
}
