package lib.baseline

import data.lib.k8s
import future.keywords

allowed_name := {
	"kernel.shm_rmid_forced",
	"net.ipv4.ip_local_port_range",
	"net.ipv4.ip_unprivileged_port_start",
	"net.ipv4.tcp_syncookies",
	"net.ipv4.ping_group_range",
}

deny_disallowed_sysctls contains msg if {
	not input.metadata.labels.allowAllSysctls
	pod := k8s.pod(input)
	some sysctl in pod.spec.securityContext.sysctls
	not sysctl.name in allowed_name
	msg := sprintf("pod %s in %s/%s uses disallowed sysctl: %s", [pod.metadata.name, input.kind, input.metadata.name, sysctl.name])
}
