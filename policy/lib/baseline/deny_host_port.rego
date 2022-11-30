package lib.baseline

import data.lib.k8s
import future.keywords

deny_host_port contains msg if {
	some container in k8s.containers(input)
	some port in container.ports
	port.hostPort != 0
	msg := sprintf("containerPort %d in container %s in %s/%s uses hostPort", [port.containerPort, container.name, input.kind, input.metadata.name])
}
