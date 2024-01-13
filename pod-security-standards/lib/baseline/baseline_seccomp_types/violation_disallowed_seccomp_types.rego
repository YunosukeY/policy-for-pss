package lib.baseline.baseline_seccomp_types

import data.lib.k8s
import data.lib.wrapper
import rego.v1

allowed_seccomp_type := {
	"RuntimeDefault",
	"Localhost",
}

violation_disallowed_seccomp_types contains msg if {
	resource := wrapper.resource(input)
	pod := k8s.pod(resource)

	not resource.metadata.labels.allowPrivilegedLevelSeccompTypes
	not pod.metadata.labels.allowPrivilegedLevelSeccompTypes

	type := pod.spec.securityContext.seccompProfile.type
	not type in allowed_seccomp_type

	msg := wrapper.format("baseline level: pod in %s/%s uses disallowed seccompProfile type: %s", [resource.kind, resource.metadata.name, type])
}

violation_disallowed_seccomp_types contains msg if {
	resource := wrapper.resource(input)
	pod := k8s.pod(resource)

	not resource.metadata.labels.allowPrivilegedLevelSeccompTypes
	not pod.metadata.labels.allowPrivilegedLevelSeccompTypes

	some container in k8s.containers(resource)
	type := container.securityContext.seccompProfile.type
	not type in allowed_seccomp_type

	msg := wrapper.format("baseline level: container %s in %s/%s uses disallowed seccompProfile type: %s", [container.name, resource.kind, resource.metadata.name, type])
}
