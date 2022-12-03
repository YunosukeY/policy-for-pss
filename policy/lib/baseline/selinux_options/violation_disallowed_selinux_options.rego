package lib.baseline.selinux_options

import data.lib.k8s
import data.lib.wrapper
import future.keywords

allowed_type := {
	"",
	"container_t",
	"container_init_t",
	"container_kvm_t",
}

violation_disallowed_selinux_options contains msg if {
	resource := wrapper.resource(input)

	not resource.metadata.labels.allowAllSeLinuxOptions

	pod := k8s.pod(resource)
	type := pod.spec.securityContext.seLinuxOptions.type
	not type in allowed_type

	msg := wrapper.format("baseline level: pod in %s/%s uses disallowed SELinux option type: %s", [resource.kind, resource.metadata.name, type])
}

violation_disallowed_selinux_options contains msg if {
	resource := wrapper.resource(input)

	not resource.metadata.labels.allowAllSeLinuxOptions

	some container in k8s.containers(resource)
	type := container.securityContext.seLinuxOptions.type
	not type in allowed_type

	msg := wrapper.format("baseline level: container %s in %s/%s uses disallowed SELinux option type: %s", [container.name, resource.kind, resource.metadata.name, type])
}

violation_disallowed_selinux_options contains msg if {
	resource := wrapper.resource(input)

	not resource.metadata.labels.allowAllSeLinuxOptions

	pod := k8s.pod(resource)
	user := pod.spec.securityContext.seLinuxOptions.user
	user != ""

	msg := wrapper.format("baseline level: pod in %s/%s uses disallowed SELinux option user: %s", [resource.kind, resource.metadata.name, user])
}

violation_disallowed_selinux_options contains msg if {
	resource := wrapper.resource(input)

	not resource.metadata.labels.allowAllSeLinuxOptions

	some container in k8s.containers(resource)
	user := container.securityContext.seLinuxOptions.user
	user != ""

	msg := wrapper.format("baseline level: container %s in %s/%s uses disallowed SELinux option user: %s", [container.name, resource.kind, resource.metadata.name, user])
}

violation_disallowed_selinux_options contains msg if {
	resource := wrapper.resource(input)

	not resource.metadata.labels.allowAllSeLinuxOptions

	pod := k8s.pod(resource)
	role := pod.spec.securityContext.seLinuxOptions.role
	role != ""

	msg := wrapper.format("baseline level: pod in %s/%s uses disallowed SELinux option role: %s", [resource.kind, resource.metadata.name, role])
}

violation_disallowed_selinux_options contains msg if {
	resource := wrapper.resource(input)

	not resource.metadata.labels.allowAllSeLinuxOptions

	some container in k8s.containers(resource)
	role := container.securityContext.seLinuxOptions.role
	role != ""

	msg := wrapper.format("baseline level: container %s in %s/%s uses disallowed SELinux option role: %s", [container.name, resource.kind, resource.metadata.name, role])
}
