package lib.restricted

import data.lib.k8s
import future.keywords

deny_run_as_root contains msg if {
	not input.metadata.labels.allowRunAsRoot
	pod := k8s.pod(input)
	not pod.spec.securityContext.runAsNonRoot
	msg := sprintf("pod %s in %s/%s runs as root", [pod.metadata.name, input.kind, input.metadata.name])
}

deny_run_as_root contains msg if {
	not input.metadata.labels.allowRunAsRoot
	some container in k8s.containers(input)
	not container.securityContext.runAsNonRoot
	msg := sprintf("container %s in %s/%s runs as root", [container.name, input.kind, input.metadata.name])
}
