package lib.baseline.app_armor_profile

import rego.v1

test_violation_disallowed_app_armor_profile if {
	pod := {
		"kind": "Pod",
		"metadata": {
			"name": "myapp-pod",
			"annotations": {
				"container.apparmor.security.beta.kubernetes.io/myapp1": "runtime/default",
				"container.apparmor.security.beta.kubernetes.io/myapp2": "localhost/profile",
				"container.apparmor.security.beta.kubernetes.io/myapp3": "unconfined",
			},
		},
	}
	violation_disallowed_app_armor_profile == {"baseline level: pod in Pod/myapp-pod uses disalloed AppArmor profile \"container.apparmor.security.beta.kubernetes.io/myapp3: unconfined\""} with input as pod
}

test_violation_disallowed_app_armor_profile if {
	pod := {
		"kind": "Pod",
		"metadata": {"name": "myapp-pod"},
	}
	count(violation_disallowed_app_armor_profile) == 0 with input as pod
}

test_violation_disallowed_app_armor_profile if {
	pod := {
		"kind": "Pod",
		"metadata": {
			"name": "myapp-pod",
			"labels": {"allowAllAppArmorProfile": true},
			"annotations": {"container.apparmor.security.beta.kubernetes.io/myapp3": "unconfined"},
		},
	}
	count(violation_disallowed_app_armor_profile) == 0 with input as pod
}
