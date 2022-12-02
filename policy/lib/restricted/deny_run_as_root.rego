package lib.restricted

import data.lib.k8s
import future.keywords

deny_run_as_root contains msg if {
	pod := k8s.pod(input)
	not pod.spec.securityContext.runAsNonRoot
	msg := sprintf("pod in %s/%s runs as root", [input.kind, input.metadata.name])
}

deny_run_as_root contains msg if {
	some container in k8s.containers(input)
	not container.securityContext.runAsNonRoot
	msg := sprintf("container %s in %s/%s runs as root", [container.name, input.kind, input.metadata.name])
}
