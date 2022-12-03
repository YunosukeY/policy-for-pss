package lib.restricted

import data.lib.k8s
import future.keywords

deny_disallowed_capabilities contains msg if {
	not input.metadata.labels.allowBaselineLevelCapabilities
	some container in k8s.containers(input)
	count({c | some c in container.securityContext.capabilities.drop; c == "ALL"}) == 0
	msg := sprintf("restricted level: container %s in %s/%s doesn't drop \"ALL\" capability", [container.name, input.kind, input.metadata.name])
}

allowed_capabilities := {"NET_BIND_SERVICE"}

deny_disallowed_capabilities contains msg if {
	not input.metadata.labels.allowBaselineLevelCapabilities
	pod := k8s.pod(input)
	not pod.spec.os.name == "windows"

	some container in k8s.containers(input)
	some c in container.securityContext.capabilities.add
	not c in allowed_capabilities
	msg := sprintf("restricted level: container %s in %s/%s has disallowed capabilities", [container.name, input.kind, input.metadata.name])
}
