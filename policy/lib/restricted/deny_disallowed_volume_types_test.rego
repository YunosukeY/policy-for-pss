package lib.restricted

import future.keywords

test_violation_disallowed_volume_types if {
	pod := {
		"kind": "Pod",
		"metadata": {"name": "myapp-pod"},
	}
	count(violation_disallowed_volume_types) == 0 with input as pod
}

test_violation_disallowed_volume_types if {
	pod := {
		"kind": "Pod",
		"metadata": {"name": "myapp-pod"},
		"spec": {"volumes": [{
			"name": "cache-volume",
			"emptyDir": {},
		}]},
	}
	count(violation_disallowed_volume_types) == 0 with input as pod
}

test_violation_disallowed_volume_types if {
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
	violation_disallowed_volume_types == {"restricted level: volume git-volume in Pod/myapp-pod has disallowed volume type"} with input as pod
}

test_violation_disallowed_volume_types if {
	pod := {
		"kind": "Pod",
		"metadata": {
			"name": "myapp-pod",
			"labels": {"allowAllVolumeTypes": true},
		},
		"spec": {"volumes": [{
			"name": "git-volume",
			"gitRepo": {
				"repository": "git@somewhere:me/my-git-repository.git",
				"revision": "22f1d8406d464b0c0874075539c1f2e96c253775",
			},
		}]},
	}
	count(violation_disallowed_volume_types) == 0 with input as pod
}
