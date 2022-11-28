package main

import data.lib.k8s

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

deny_disallowed_capabilities[msg] {
	container := k8s.containers(input)[_]
	count({c | c := container.securityContext.capabilities.add[_]; not allowed_capabilities[c]}) != 0
	msg := sprintf("container %s in %s/%s has disallowed capabilities", [container.name, input.kind, input.metadata.name])
}
