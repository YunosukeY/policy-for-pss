package lib.restricted.restricted_capabilities

import data.lib.k8s
import data.lib.wrapper
import future.keywords

violation_disallowed_capabilities contains msg if {
	resource := wrapper.resource(input)

	not resource.metadata.labels.allowBaselineLevelCapabilities

	some container in k8s.containers(resource)
	count({c | some c in container.securityContext.capabilities.drop; c == "ALL"}) == 0

	msg := wrapper.format("restricted level: container %s in %s/%s doesn't drop \"ALL\" capability", [container.name, resource.kind, resource.metadata.name])
}

allowed_capabilities := {"NET_BIND_SERVICE"}

violation_disallowed_capabilities contains msg if {
	resource := wrapper.resource(input)

	not resource.metadata.labels.allowBaselineLevelCapabilities

	pod := k8s.pod(resource)
	not pod.spec.os.name == "windows"

	some container in k8s.containers(resource)
	some c in container.securityContext.capabilities.add
	not c in allowed_capabilities

	msg := wrapper.format("restricted level: container %s in %s/%s has disallowed capabilities", [container.name, resource.kind, resource.metadata.name])
}
