package lib.restricted

import data.lib.k8s
import future.keywords

deny_disallowed_volume_types contains msg if {
	pod := k8s.pod(input)
	some volume in pod.spec.volumes

	not volume.configMap
	not volume.csi
	not volume.downwardAPI
	not volume.emptyDir
	not volume.ephemeral
	not volume.persistentVolumeClaim
	not volume.projected
	not volume.secret

	msg := sprintf("volume %s in %s/%s has disallowed volume type", [volume.name, input.kind, input.metadata.name])
}
