package lib.restricted.volume_types

import data.lib.k8s
import data.lib.wrapper
import future.keywords

violation_disallowed_volume_types contains msg if {
	resource := wrapper.resource(input)
	pod := k8s.pod(resource)

	not resource.metadata.labels.allowAllVolumeTypes
	not pod.metadata.labels.allowAllVolumeTypes

	some volume in pod.spec.volumes
	not volume.configMap
	not volume.csi
	not volume.downwardAPI
	not volume.emptyDir
	not volume.ephemeral
	not volume.persistentVolumeClaim
	not volume.projected
	not volume.secret

	msg := wrapper.format("restricted level: volume %s in %s/%s has disallowed volume type", [volume.name, resource.kind, resource.metadata.name])
}
