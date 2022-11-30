package lib.baseline

test_deny_disallowed_app_armor_profile {
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
	deny_disallowed_app_armor_profile == {"pod myapp-pod in Pod/myapp-pod uses disalloed AppArmor profile \"container.apparmor.security.beta.kubernetes.io/myapp3: unconfined\""} with input as pod
}

test_deny_disallowed_app_armor_profile {
	pod := {
		"kind": "Pod",
		"metadata": {"name": "myapp-pod"},
	}
	count(deny_disallowed_app_armor_profile) == 0 with input as pod
}