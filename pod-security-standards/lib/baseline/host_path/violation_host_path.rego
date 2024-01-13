package lib.baseline.host_path

import data.lib.k8s
import data.lib.wrapper
import rego.v1

violation_host_path contains msg if {
	resource := wrapper.resource(input)
	pod := k8s.pod(resource)

	not resource.metadata.labels.allowHostPath
	not pod.metadata.labels.allowHostPath

	some volume in pod.spec.volumes
	volume.hostPath

	msg := wrapper.format("baseline level: volume %s in %s/%s uses hostPath", [volume.name, resource.kind, resource.metadata.name])
}
