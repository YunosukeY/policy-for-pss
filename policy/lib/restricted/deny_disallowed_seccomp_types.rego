package lib.restricted

import data.lib.k8s
import future.keywords

allowed_seccomp_type := {
	"RuntimeDefault",
	"Localhost",
}

deny_disallowed_seccomp_types contains msg if {
	not input.metadata.labels.allowBaselineLevelSeccompTypes

	pod := k8s.pod(input)
	not pod.spec.os.name == "windows"

	type := pod.spec.securityContext.seccompProfile.type
	not type in allowed_seccomp_type
	msg := sprintf("pod in %s/%s uses disallowed seccompProfile type: %s", [input.kind, input.metadata.name, type])
}

deny_disallowed_seccomp_types contains msg if {
	not input.metadata.labels.allowBaselineLevelSeccompTypes

	pod := k8s.pod(input)
	not pod.spec.os.name == "windows"

	some container in k8s.containers(input)
	type := container.securityContext.seccompProfile.type
	not type in allowed_seccomp_type
	msg := sprintf("container %s in %s/%s uses disallowed seccompProfile type: %s", [container.name, input.kind, input.metadata.name, type])
}

deny_disallowed_seccomp_types contains msg if {
	not input.metadata.labels.allowBaselineLevelSeccompTypes

	pod := k8s.pod(input)
	not pod.spec.os.name == "windows"

	not pod.spec.securityContext.seccompProfile.type
	msg := sprintf("pod in %s/%s must be set seccomp profile", [input.kind, input.metadata.name])
}

deny_disallowed_seccomp_types contains msg if {
	not input.metadata.labels.allowBaselineLevelSeccompTypes

	pod := k8s.pod(input)
	not pod.spec.os.name == "windows"

	some container in k8s.containers(input)
	not container.securityContext.seccompProfile.type
	msg := sprintf("container %s in %s/%s must be set seccomp profile", [container.name, input.kind, input.metadata.name])
}
