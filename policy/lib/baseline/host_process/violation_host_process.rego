package lib.baseline.host_process

import data.lib.k8s
import data.lib.wrapper
import future.keywords

violation_host_process contains msg if {
	resource := wrapper.resource(input)

	not resource.metadata.labels.allowHostProcess

	pod := k8s.pod(resource)
	pod.spec.securityContext.windowsOptions.hostProcess

	msg := wrapper.format("baseline level: pod in %s/%s uses hostProcess", [resource.kind, resource.metadata.name])
}

violation_host_process contains msg if {
	resource := wrapper.resource(input)

	not resource.metadata.labels.allowHostProcess

	some container in k8s.containers(resource)
	container.securityContext.windowsOptions.hostProcess

	msg := wrapper.format("baseline level: container %s in %s/%s uses hostProcess", [container.name, resource.kind, resource.metadata.name])
}
