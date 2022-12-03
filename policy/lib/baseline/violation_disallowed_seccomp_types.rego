package lib.baseline

import data.lib.k8s
import future.keywords

allowed_seccomp_type := {
	"RuntimeDefault",
	"Localhost",
}

violation_disallowed_seccomp_types contains msg if {
	not input.metadata.labels.allowPrivilegedLevelSeccompTypes
	pod := k8s.pod(input)
	type := pod.spec.securityContext.seccompProfile.type
	not type in allowed_seccomp_type
	msg := sprintf("baseline level: pod in %s/%s uses disallowed seccompProfile type: %s", [input.kind, input.metadata.name, type])
}

violation_disallowed_seccomp_types contains msg if {
	not input.metadata.labels.allowPrivilegedLevelSeccompTypes
	some container in k8s.containers(input)
	type := container.securityContext.seccompProfile.type
	not type in allowed_seccomp_type
	msg := sprintf("baseline level: container %s in %s/%s uses disallowed seccompProfile type: %s", [container.name, input.kind, input.metadata.name, type])
}
