package lib.restricted

import data.lib.k8s
import data.lib.wrapper
import future.keywords

violation_run_as_root_user contains msg if {
	resource := wrapper.resource(input)

	not resource.metadata.labels.allowRunAsRootUser

	pod := k8s.pod(resource)
	pod.spec.securityContext.runAsUser == 0

	msg := wrapper.format("restricted level: pod in %s/%s runs as root", [resource.kind, resource.metadata.name])
}

violation_run_as_root_user contains msg if {
	resource := wrapper.resource(input)

	not resource.metadata.labels.allowRunAsRootUser

	some container in k8s.containers(resource)
	container.securityContext.runAsUser == 0

	msg := wrapper.format("restricted level: container %s in %s/%s runs as root", [container.name, resource.kind, resource.metadata.name])
}
