package lib.baseline

import data.lib.k8s
import data.lib.wrapper
import future.keywords

violation_host_path contains msg if {
	resource := wrapper.resource(input)

	not resource.metadata.labels.allowHostPath

	pod := k8s.pod(resource)
	some volume in pod.spec.volumes
	volume.hostPath

	msg := wrapper.format("baseline level: volume %s in %s/%s uses hostPath", [volume.name, resource.kind, resource.metadata.name])
}
