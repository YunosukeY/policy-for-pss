package lib.baseline

import data.lib.k8s
import future.keywords

allowed_type := {
	"",
	"container_t",
	"container_init_t",
	"container_kvm_t",
}

deny_disallowed_selinux_options contains msg if {
	pod := k8s.pod(input)
	type := pod.spec.securityContext.seLinuxOptions.type
	not type in allowed_type
	msg := sprintf("pod in %s/%s uses disallowed SELinux option type: %s", [input.kind, input.metadata.name, type])
}

deny_disallowed_selinux_options contains msg if {
	some container in k8s.containers(input)
	type := container.securityContext.seLinuxOptions.type
	not type in allowed_type
	msg := sprintf("container %s in %s/%s uses disallowed SELinux option type: %s", [container.name, input.kind, input.metadata.name, type])
}

deny_disallowed_selinux_options contains msg if {
	pod := k8s.pod(input)
	user := pod.spec.securityContext.seLinuxOptions.user
	user != ""
	msg := sprintf("pod in %s/%s uses disallowed SELinux option user: %s", [input.kind, input.metadata.name, user])
}

deny_disallowed_selinux_options contains msg if {
	some container in k8s.containers(input)
	user := container.securityContext.seLinuxOptions.user
	user != ""
	msg := sprintf("container %s in %s/%s uses disallowed SELinux option user: %s", [container.name, input.kind, input.metadata.name, user])
}

deny_disallowed_selinux_options contains msg if {
	pod := k8s.pod(input)
	role := pod.spec.securityContext.seLinuxOptions.role
	role != ""
	msg := sprintf("pod in %s/%s uses disallowed SELinux option role: %s", [input.kind, input.metadata.name, role])
}

deny_disallowed_selinux_options contains msg if {
	some container in k8s.containers(input)
	role := container.securityContext.seLinuxOptions.role
	role != ""
	msg := sprintf("container %s in %s/%s uses disallowed SELinux option role: %s", [container.name, input.kind, input.metadata.name, role])
}
