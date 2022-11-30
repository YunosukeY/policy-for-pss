package lib.baseline

import data.lib.k8s

allowed_profile(profile) {
	profile == "runtime/default"
}

allowed_profile(profile) {
	startswith(profile, "localhost/")
}

deny_disallowed_app_armor_profile[msg] {
	pod := k8s.pod(input)

	some name
	value := pod.metadata.annotations[name]
	startswith(name, "container.apparmor.security.beta.kubernetes.io/")
	not allowed_profile(value)

	msg := sprintf("pod %s in %s/%s uses disalloed AppArmor profile \"%s: %s\"", [pod.metadata.name, input.kind, input.metadata.name, name, value])
}
