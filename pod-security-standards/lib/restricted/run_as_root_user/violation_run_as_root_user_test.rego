package lib.restricted.run_as_root_user

import rego.v1

test_violation_run_as_root_user if {
	pod := {
		"kind": "Pod",
		"metadata": {"name": "myapp-pod"},
	}
	count(violation_run_as_root_user) == 0 with input as pod
}

test_violation_run_as_root_user if {
	pod := {
		"kind": "Pod",
		"metadata": {"name": "myapp-pod"},
		"spec": {"securityContext": {"runAsUser": 999}},
	}
	count(violation_run_as_root_user) == 0 with input as pod
}

test_violation_run_as_root_user if {
	pod := {
		"kind": "Pod",
		"metadata": {"name": "myapp-pod"},
		"spec": {"securityContext": {"runAsUser": 0}},
	}
	violation_run_as_root_user == {"restricted level: pod in Pod/myapp-pod runs as root"} with input as pod
}

test_violation_run_as_root_user if {
	pod := {
		"kind": "Pod",
		"metadata": {"name": "myapp-pod"},
		"spec": {"containers": [
			{
				"name": "myapp1",
				"image": "busybox:1.28",
				"command": ["sh", "-c", "echo The app is running! && sleep 3600"],
			},
			{
				"name": "myapp2",
				"image": "busybox:1.28",
				"command": ["sh", "-c", "echo The app is running! && sleep 3600"],
				"securityContext": {"runAsUser": 999},
			},
			{
				"name": "myapp3",
				"image": "busybox:1.28",
				"command": ["sh", "-c", "echo The app is running! && sleep 3600"],
				"securityContext": {"runAsUser": 0},
			},
		]},
	}
	violation_run_as_root_user == {"restricted level: container myapp3 in Pod/myapp-pod runs as root"} with input as pod
}

test_violation_run_as_root_user if {
	pod := {
		"kind": "Pod",
		"metadata": {
			"name": "myapp-pod",
			"labels": {"allowRunAsRootUser": true},
		},
		"spec": {
			"securityContext": {"runAsUser": 0},
			"containers": [{
				"name": "myapp3",
				"image": "busybox:1.28",
				"command": ["sh", "-c", "echo The app is running! && sleep 3600"],
				"securityContext": {"runAsUser": 0},
			}],
		},
	}
	count(violation_run_as_root_user) == 0 with input as pod
}
