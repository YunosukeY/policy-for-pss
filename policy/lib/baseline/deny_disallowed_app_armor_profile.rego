package lib.baseline

import data.lib.k8s
import future.keywords

allowed_profile(profile) if {
	profile == "runtime/default"
}

allowed_profile(profile) if {
	startswith(profile, "localhost/")
}

deny_disallowed_app_armor_profile contains msg if {
	pod := k8s.pod(input)

	some name
	value := pod.metadata.annotations[name]
	startswith(name, "container.apparmor.security.beta.kubernetes.io/")
	not allowed_profile(value)

	msg := sprintf("pod %s in %s/%s uses disalloed AppArmor profile \"%s: %s\"", [pod.metadata.name, input.kind, input.metadata.name, name, value])
}
