package lib.baseline.host_namespaces

import data.lib.k8s
import data.lib.wrapper
import future.keywords

violation_host_namespaces contains msg if {
	resource := wrapper.resource(input)

	not resource.metadata.labels.allowHostNamespace

	pod := k8s.pod(resource)
	pod.spec.hostNetwork

	msg := wrapper.format("baseline level: pod in %s/%s uses hostNetWork", [resource.kind, resource.metadata.name])
}

violation_host_namespaces contains msg if {
	resource := wrapper.resource(input)

	not resource.metadata.labels.allowHostNamespace

	pod := k8s.pod(resource)
	pod.spec.hostPID

	msg := wrapper.format("baseline level: pod in %s/%s uses hostPID", [resource.kind, resource.metadata.name])
}

violation_host_namespaces contains msg if {
	resource := wrapper.resource(input)

	not resource.metadata.labels.allowHostNamespace

	pod := k8s.pod(resource)
	pod.spec.hostIPC

	msg := wrapper.format("baseline level: pod in %s/%s uses hostIPC", [resource.kind, resource.metadata.name])
}
