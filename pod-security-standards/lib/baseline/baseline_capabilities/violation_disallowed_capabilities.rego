package lib.baseline.baseline_capabilities

import data.lib.k8s
import data.lib.wrapper
import rego.v1

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

violation_disallowed_capabilities contains msg if {
	resource := wrapper.resource(input)
	pod := k8s.pod(resource)

	not resource.metadata.labels.allowPrivilegedLevelCapabilities
	not pod.metadata.labels.allowPrivilegedLevelCapabilities

	some container in k8s.containers(resource)
	some c in container.securityContext.capabilities.add
	not c in allowed_capabilities

	msg := wrapper.format("baseline level: container %s in %s/%s has disallowed capabilities", [container.name, resource.kind, resource.metadata.name])
}
