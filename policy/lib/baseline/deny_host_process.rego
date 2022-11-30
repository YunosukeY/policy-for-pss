package lib.baseline

import data.lib.k8s
import future.keywords

deny_host_process contains msg if {
	pod := k8s.pod(input)
	pod.spec.securityContext.windowsOptions.hostProcess
	msg := sprintf("pod %s in %s/%s uses hostProcess", [pod.metadata.name, input.kind, input.metadata.name])
}

deny_host_process contains msg if {
	some container in k8s.containers(input)
	container.securityContext.windowsOptions.hostProcess
	msg := sprintf("container %s in %s/%s uses hostProcess", [container.name, input.kind, input.metadata.name])
}
