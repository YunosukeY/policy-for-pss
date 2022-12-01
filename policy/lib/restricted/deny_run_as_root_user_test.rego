package lib.restricted

import future.keywords

test_deny_run_as_root_user if {
	pod := {
		"kind": "Pod",
		"metadata": {"name": "myapp-pod"},
	}
	count(deny_run_as_root_user) == 0 with input as pod
}

test_deny_run_as_root_user if {
	pod := {
		"kind": "Pod",
		"metadata": {"name": "myapp-pod"},
		"spec": {"securityContext": {"runAsUser": 999}},
	}
	count(deny_run_as_root_user) == 0 with input as pod
}

test_deny_run_as_root_user if {
	pod := {
		"kind": "Pod",
		"metadata": {"name": "myapp-pod"},
		"spec": {"securityContext": {"runAsUser": 0}},
	}
	deny_run_as_root_user == {"pod myapp-pod in Pod/myapp-pod runs as root"} with input as pod
}

test_deny_run_as_root_user if {
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
	deny_run_as_root_user == {"container myapp3 in Pod/myapp-pod runs as root"} with input as pod
}

test_deny_run_as_root_user if {
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
	count(deny_run_as_root_user) == 0 with input as pod
}
