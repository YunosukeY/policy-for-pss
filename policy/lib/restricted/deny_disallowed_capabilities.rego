package lib.restricted

import data.lib.k8s

deny_disallowed_capabilities[msg] {
	container := k8s.containers(input)[_]
	{c | c := container.securityContext.capabilities.drop[_]; c == "ALL"} != {"ALL"}
	msg := sprintf("container %s in %s/%s doesn't drop \"ALL\" capability", [container.name, input.kind, input.metadata.name])
}

allowed_capabilities := {"NET_BIND_SERVICE"}

deny_disallowed_capabilities[msg] {
	p := k8s.pod(input)
	{n | n := p.spec.os.name; n == "windows"} != {"windows"}

	container := k8s.containers(input)[_]
	count({c | c := container.securityContext.capabilities.add[_]; not allowed_capabilities[c]}) != 0
	msg := sprintf("container %s in %s/%s has disallowed capabilities", [container.name, input.kind, input.metadata.name])
	print(container.name)
}
