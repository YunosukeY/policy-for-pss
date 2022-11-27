package main

test_deny_run_as_root {
	pod := {
		"kind": "Pod",
		"metadata": {"name": "myapp-pod"},
		"spec": {"containers": [
			{
				"name": "myapp",
				"image": "busybox:1.28",
				"command": ["sh", "-c", "echo The app is running! && sleep 3600"],
			},
			{
				"name": "non-root-myapp",
				"image": "busybox:1.28",
				"command": ["sh", "-c", "echo The app is running! && sleep 3600"],
				"securityContext": {"runAsNonRoot": true},
			},
			{
				"name": "root-myapp",
				"image": "busybox:1.28",
				"command": ["sh", "-c", "echo The app is running! && sleep 3600"],
				"securityContext": {"runAsNonRoot": false},
			},
		]},
	}
	deny_run_as_root == {
		"pod myapp-pod in Pod/myapp-pod runs as root",
		"container myapp in Pod/myapp-pod runs as root",
		"container root-myapp in Pod/myapp-pod runs as root",
	} with input as pod

	non_root_pod := {
		"kind": "Pod",
		"metadata": {"name": "myapp-pod"},
		"spec": {"securityContext": {"runAsNonRoot": true}},
	}
	count(deny_run_as_root) == 0 with input as non_root_pod

	root_pod := {
		"kind": "Pod",
		"metadata": {"name": "myapp-pod"},
		"spec": {"securityContext": {"runAsNonRoot": false}},
	}
	deny_run_as_root == {"pod myapp-pod in Pod/myapp-pod runs as root"} with input as root_pod
}
