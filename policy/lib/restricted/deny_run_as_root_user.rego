package lib.restricted

import data.lib.k8s
import future.keywords

deny_run_as_root_user contains msg if {
	pod := k8s.pod(input)
	pod.spec.securityContext.runAsUser == 0
	msg := sprintf("pod %s in %s/%s runs as root", [pod.metadata.name, input.kind, input.metadata.name])
}

deny_run_as_root_user contains msg if {
	some container in k8s.containers(input)
	container.securityContext.runAsUser == 0
	msg := sprintf("container %s in %s/%s runs as root", [container.name, input.kind, input.metadata.name])
}
