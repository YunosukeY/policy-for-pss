package lib.restricted

import data.lib.k8s
import data.lib.wrapper
import future.keywords

allowed_seccomp_type := {
	"RuntimeDefault",
	"Localhost",
}

violation_disallowed_seccomp_types contains msg if {
	resource := wrapper.resource(input)

	not resource.metadata.labels.allowBaselineLevelSeccompTypes

	pod := k8s.pod(resource)
	not pod.spec.os.name == "windows"

	type := pod.spec.securityContext.seccompProfile.type
	not type in allowed_seccomp_type

	msg := wrapper.format("restricted level: pod in %s/%s uses disallowed seccompProfile type: %s", [resource.kind, resource.metadata.name, type])
}

violation_disallowed_seccomp_types contains msg if {
	resource := wrapper.resource(input)

	not resource.metadata.labels.allowBaselineLevelSeccompTypes

	pod := k8s.pod(resource)
	not pod.spec.os.name == "windows"

	some container in k8s.containers(resource)
	type := container.securityContext.seccompProfile.type
	not type in allowed_seccomp_type

	msg := wrapper.format("restricted level: container %s in %s/%s uses disallowed seccompProfile type: %s", [container.name, resource.kind, resource.metadata.name, type])
}

violation_disallowed_seccomp_types contains msg if {
	resource := wrapper.resource(input)

	not resource.metadata.labels.allowBaselineLevelSeccompTypes

	pod := k8s.pod(resource)
	not pod.spec.os.name == "windows"

	not pod.spec.securityContext.seccompProfile.type

	msg := wrapper.format("restricted level: pod in %s/%s must be set seccomp profile", [resource.kind, resource.metadata.name])
}

violation_disallowed_seccomp_types contains msg if {
	resource := wrapper.resource(input)

	not resource.metadata.labels.allowBaselineLevelSeccompTypes

	pod := k8s.pod(resource)
	not pod.spec.os.name == "windows"

	some container in k8s.containers(resource)
	not container.securityContext.seccompProfile.type

	msg := wrapper.format("restricted level: container %s in %s/%s must be set seccomp profile", [container.name, resource.kind, resource.metadata.name])
}
