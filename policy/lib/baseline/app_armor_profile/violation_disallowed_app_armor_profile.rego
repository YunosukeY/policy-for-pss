package lib.baseline.app_armor_profile

import data.lib.k8s
import data.lib.wrapper
import future.keywords

allowed_profile(profile) if {
	profile == "runtime/default"
}

allowed_profile(profile) if {
	startswith(profile, "localhost/")
}

violation_disallowed_app_armor_profile contains msg if {
	resource := wrapper.resource(input)
	pod := k8s.pod(resource)

	not resource.metadata.labels.allowAllAppArmorProfile
	not pod.metadata.labels.allowAllAppArmorProfile

	some name
	value := pod.metadata.annotations[name]
	startswith(name, "container.apparmor.security.beta.kubernetes.io/")
	not allowed_profile(value)

	msg := wrapper.format("baseline level: pod in %s/%s uses disalloed AppArmor profile \"%s: %s\"", [resource.kind, resource.metadata.name, name, value])
}
