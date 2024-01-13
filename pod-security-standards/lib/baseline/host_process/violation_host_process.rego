package lib.baseline.host_process

import data.lib.k8s
import data.lib.wrapper
import rego.v1

violation_host_process contains msg if {
	resource := wrapper.resource(input)
	pod := k8s.pod(resource)

	not resource.metadata.labels.allowHostProcess
	not pod.metadata.labels.allowHostProcess

	pod.spec.securityContext.windowsOptions.hostProcess

	msg := wrapper.format("baseline level: pod in %s/%s uses hostProcess", [resource.kind, resource.metadata.name])
}

violation_host_process contains msg if {
	resource := wrapper.resource(input)
	pod := k8s.pod(resource)

	not resource.metadata.labels.allowHostProcess
	not pod.metadata.labels.allowHostProcess

	some container in k8s.containers(resource)
	container.securityContext.windowsOptions.hostProcess

	msg := wrapper.format("baseline level: container %s in %s/%s uses hostProcess", [container.name, resource.kind, resource.metadata.name])
}
