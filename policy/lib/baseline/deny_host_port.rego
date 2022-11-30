package lib.baseline

import data.lib.k8s
import future.keywords

deny_host_port contains msg if {
	container := k8s.containers(input)[_]
	some port in container.ports
	port.hostPort != 0
	msg := sprintf("containerPort %d in container %s in %s/%s uses hostPort", [port.containerPort, container.name, input.kind, input.metadata.name])
}
