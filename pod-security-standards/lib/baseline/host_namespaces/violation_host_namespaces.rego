package lib.baseline.host_namespaces

import data.lib.k8s
import data.lib.wrapper
import rego.v1

violation_host_namespaces contains msg if {
	resource := wrapper.resource(input)
	pod := k8s.pod(resource)

	not resource.metadata.labels.allowHostNamespace
	not pod.metadata.labels.allowHostNamespace

	pod.spec.hostNetwork

	msg := wrapper.format("baseline level: pod in %s/%s uses hostNetWork", [resource.kind, resource.metadata.name])
}

violation_host_namespaces contains msg if {
	resource := wrapper.resource(input)
	pod := k8s.pod(resource)

	not resource.metadata.labels.allowHostNamespace
	not pod.metadata.labels.allowHostNamespace

	pod.spec.hostPID

	msg := wrapper.format("baseline level: pod in %s/%s uses hostPID", [resource.kind, resource.metadata.name])
}

violation_host_namespaces contains msg if {
	resource := wrapper.resource(input)
	pod := k8s.pod(resource)

	not resource.metadata.labels.allowHostNamespace
	not pod.metadata.labels.allowHostNamespace

	pod.spec.hostIPC

	msg := wrapper.format("baseline level: pod in %s/%s uses hostIPC", [resource.kind, resource.metadata.name])
}
