package lib.restricted.run_as_root

import data.lib.k8s
import data.lib.wrapper
import future.keywords

violation_run_as_root contains msg if {
	resource := wrapper.resource(input)
	pod := k8s.pod(resource)

	not resource.metadata.labels.allowRunAsRoot
	not pod.metadata.labels.allowRunAsRoot

	not pod.spec.securityContext.runAsNonRoot

	msg := wrapper.format("restricted level: pod in %s/%s runs as root", [resource.kind, resource.metadata.name])
}

violation_run_as_root contains msg if {
	resource := wrapper.resource(input)
	pod := k8s.pod(resource)

	not resource.metadata.labels.allowRunAsRoot
	not pod.metadata.labels.allowRunAsRoot

	some container in k8s.containers(resource)
	not container.securityContext.runAsNonRoot

	msg := wrapper.format("restricted level: container %s in %s/%s runs as root", [container.name, resource.kind, resource.metadata.name])
}
