package lib.baseline.sysctls

import data.lib.k8s
import data.lib.wrapper
import rego.v1

allowed_name := {
	"kernel.shm_rmid_forced",
	"net.ipv4.ip_local_port_range",
	"net.ipv4.ip_unprivileged_port_start",
	"net.ipv4.tcp_syncookies",
	"net.ipv4.ping_group_range",
}

violation_disallowed_sysctls contains msg if {
	resource := wrapper.resource(input)
	pod := k8s.pod(resource)

	not resource.metadata.labels.allowAllSysctls
	not pod.metadata.labels.allowAllSysctls

	some sysctl in pod.spec.securityContext.sysctls
	not sysctl.name in allowed_name

	msg := wrapper.format("baseline level: pod in %s/%s uses disallowed sysctl: %s", [resource.kind, resource.metadata.name, sysctl.name])
}
