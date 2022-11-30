package lib.baseline

import data.lib.k8s
import future.keywords

allowed_capabilities := {
	"AUDIT_WRITE",
	"CHOWN",
	"DAC_OVERRIDE",
	"FOWNER",
	"FSETID",
	"KILL",
	"MKNOD",
	"NET_BIND_SERVICE",
	"SETFCAP",
	"SETGID",
	"SETPCAP",
	"SETUID",
	"SYS_CHROOT",
}

deny_disallowed_capabilities contains msg if {
	some container in k8s.containers(input)
	count({c | some c in container.securityContext.capabilities.add; not c in allowed_capabilities}) != 0
	msg := sprintf("container %s in %s/%s has disallowed capabilities", [container.name, input.kind, input.metadata.name])
}
