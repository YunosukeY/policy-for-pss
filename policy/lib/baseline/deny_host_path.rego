package lib.baseline

import data.lib.k8s

deny_host_path[msg] {
	pod := k8s.pod(input)
	volume := pod.spec.volumes[_]
	volume.hostPath
	msg := sprintf("volume %s in pod %s in %s/%s uses hostPath", [volume.name, pod.metadata.name, input.kind, input.metadata.name])
}
