package main

import data.lib.k8s

deny_run_as_root[msg] {
	pod := k8s.pod(input)
	not pod.spec.securityContext.runAsNonRoot
	print(pod.metadata.name)
	msg := sprintf("pod %s in %s/%s runs as root", [pod.metadata.name, input.kind, input.metadata.name])
}

deny_run_as_root[msg] {
	container := k8s.containers(input)[_]
	not container.securityContext.runAsNonRoot
	print(container.name)
	msg := sprintf("container %s in %s/%s runs as root", [container.name, input.kind, input.metadata.name])
}
