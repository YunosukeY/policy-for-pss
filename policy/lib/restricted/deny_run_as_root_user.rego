package lib.restricted

import data.lib.k8s
import future.keywords

deny_run_as_root_user contains msg if {
	not input.metadata.labels.allowRunAsRootUser
	pod := k8s.pod(input)
	pod.spec.securityContext.runAsUser == 0
	msg := sprintf("restricted level: pod in %s/%s runs as root", [input.kind, input.metadata.name])
}

deny_run_as_root_user contains msg if {
	not input.metadata.labels.allowRunAsRootUser
	some container in k8s.containers(input)
	container.securityContext.runAsUser == 0
	msg := sprintf("restricted level: container %s in %s/%s runs as root", [container.name, input.kind, input.metadata.name])
}
