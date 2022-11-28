package lib.baseline

import data.lib.k8s

deny_host_process[msg] {
	pod := k8s.pod(input)
	pod.spec.securityContext.windowsOptions.hostProcess
	msg := sprintf("pod %s in %s/%s uses hostProcess", [pod.metadata.name, input.kind, input.metadata.name])
}

deny_host_process[msg] {
	container := k8s.containers(input)[_]
	container.securityContext.windowsOptions.hostProcess
	msg := sprintf("container %s in %s/%s uses hostProcess", [container.name, input.kind, input.metadata.name])
}
