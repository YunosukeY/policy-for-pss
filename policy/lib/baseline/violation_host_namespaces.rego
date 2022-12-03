package lib.baseline

import data.lib.k8s
import future.keywords

violation_host_namespaces contains msg if {
	not input.metadata.labels.allowHostNamespace
	pod := k8s.pod(input)
	pod.spec.hostNetwork
	msg := sprintf("baseline level: pod in %s/%s uses hostNetWork", [input.kind, input.metadata.name])
}

violation_host_namespaces contains msg if {
	not input.metadata.labels.allowHostNamespace
	pod := k8s.pod(input)
	pod.spec.hostPID
	msg := sprintf("baseline level: pod in %s/%s uses hostPID", [input.kind, input.metadata.name])
}

violation_host_namespaces contains msg if {
	not input.metadata.labels.allowHostNamespace
	pod := k8s.pod(input)
	pod.spec.hostIPC
	msg := sprintf("baseline level: pod in %s/%s uses hostIPC", [input.kind, input.metadata.name])
}
