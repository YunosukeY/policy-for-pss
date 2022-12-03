package lib.baseline.host_port

import data.lib.k8s
import data.lib.wrapper
import future.keywords

violation_host_port contains msg if {
	resource := wrapper.resource(input)

	not resource.metadata.labels.allowHostPort

	some container in k8s.containers(resource)
	some port in container.ports
	port.hostPort != 0

	msg := wrapper.format("baseline level: containerPort %d in container %s in %s/%s uses hostPort", [port.containerPort, container.name, resource.kind, resource.metadata.name])
}
