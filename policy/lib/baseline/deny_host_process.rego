package lib.baseline

import data.lib.k8s
import future.keywords

deny_host_process contains msg if {
	not input.metadata.labels.allowHostProcess
	pod := k8s.pod(input)
	pod.spec.securityContext.windowsOptions.hostProcess
	msg := sprintf("baseline level: pod in %s/%s uses hostProcess", [input.kind, input.metadata.name])
}

deny_host_process contains msg if {
	not input.metadata.labels.allowHostProcess
	some container in k8s.containers(input)
	container.securityContext.windowsOptions.hostProcess
	msg := sprintf("baseline level: container %s in %s/%s uses hostProcess", [container.name, input.kind, input.metadata.name])
}
