package lib.restricted

import data.lib.k8s
import future.keywords

deny_disallowed_capabilities contains msg if {
	some container in k8s.containers(input)
	{c | some c in container.securityContext.capabilities.drop} & {"ALL"} != {"ALL"}
	msg := sprintf("container %s in %s/%s doesn't drop \"ALL\" capability", [container.name, input.kind, input.metadata.name])
}

allowed_capabilities := {"NET_BIND_SERVICE"}

deny_disallowed_capabilities contains msg if {
	p := k8s.pod(input)
	{n | n := p.spec.os.name; n == "windows"} != {"windows"}

	some container in k8s.containers(input)
	count({c | some c in container.securityContext.capabilities.add; not c in allowed_capabilities}) != 0
	msg := sprintf("container %s in %s/%s has disallowed capabilities", [container.name, input.kind, input.metadata.name])
}
