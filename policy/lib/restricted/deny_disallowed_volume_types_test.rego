package lib.restricted

import future.keywords

test_deny_disallowed_volume_types if {
	pod := {
		"kind": "Pod",
		"metadata": {"name": "myapp-pod"},
	}
	count(deny_disallowed_volume_types) == 0 with input as pod
}

test_deny_disallowed_volume_types if {
	pod := {
		"kind": "Pod",
		"metadata": {"name": "myapp-pod"},
		"spec": {"volumes": [{
			"name": "cache-volume",
			"emptyDir": {},
		}]},
	}
	count(deny_disallowed_volume_types) == 0 with input as pod
}

test_deny_disallowed_volume_types if {
	pod := {
		"kind": "Pod",
		"metadata": {"name": "myapp-pod"},
		"spec": {"volumes": [{
			"name": "git-volume",
			"gitRepo": {
				"repository": "git@somewhere:me/my-git-repository.git",
				"revision": "22f1d8406d464b0c0874075539c1f2e96c253775",
			},
		}]},
	}
	deny_disallowed_volume_types == {"volume git-volume in Pod/myapp-pod has disallowed volume type"} with input as pod
}
