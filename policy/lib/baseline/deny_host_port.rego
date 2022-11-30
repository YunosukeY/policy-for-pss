package lib.baseline

import data.lib.k8s

deny_host_port[msg] {
	container := k8s.containers(input)[_]
	port := container.ports[_]
	port.hostPort != 0
	msg := sprintf("containerPort %d in container %s in %s/%s uses hostPort", [port.containerPort, container.name, input.kind, input.metadata.name])
}
