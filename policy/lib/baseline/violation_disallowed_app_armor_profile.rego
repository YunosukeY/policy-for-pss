package lib.baseline

import data.lib.k8s
import future.keywords

allowed_profile(profile) if {
	profile == "runtime/default"
}

allowed_profile(profile) if {
	startswith(profile, "localhost/")
}

violation_disallowed_app_armor_profile contains msg if {
	not input.metadata.labels.allowAllAppArmorProfile

	pod := k8s.pod(input)

	some name
	value := pod.metadata.annotations[name]
	startswith(name, "container.apparmor.security.beta.kubernetes.io/")
	not allowed_profile(value)

	msg := sprintf("baseline level: pod in %s/%s uses disalloed AppArmor profile \"%s: %s\"", [input.kind, input.metadata.name, name, value])
}
