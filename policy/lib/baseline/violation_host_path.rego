package lib.baseline

import data.lib.k8s
import future.keywords

violation_host_path contains msg if {
	not input.metadata.labels.allowHostPath
	pod := k8s.pod(input)
	some volume in pod.spec.volumes
	volume.hostPath
	msg := sprintf("baseline level: volume %s in %s/%s uses hostPath", [volume.name, input.kind, input.metadata.name])
}
