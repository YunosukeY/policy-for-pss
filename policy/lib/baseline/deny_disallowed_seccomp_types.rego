package lib.baseline

import data.lib.k8s
import future.keywords

allowed_seccomp_type := {
	"RuntimeDefault",
	"Localhost",
}

deny_disallowed_seccomp_types contains msg if {
	pod := k8s.pod(input)
	type := pod.spec.securityContext.seccompProfile.type
	not type in allowed_seccomp_type
	msg := sprintf("pod %s in %s/%s uses disallowed seccompProfile type: %s", [pod.metadata.name, input.kind, input.metadata.name, type])
}

deny_disallowed_seccomp_types contains msg if {
	some container in k8s.containers(input)
	type := container.securityContext.seccompProfile.type
	not type in allowed_seccomp_type
	msg := sprintf("container %s in %s/%s uses disallowed seccompProfile type: %s", [container.name, input.kind, input.metadata.name, type])
}
