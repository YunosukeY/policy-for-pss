package lib.baseline

import future.keywords

test_deny_host_process if {
	pod := {
		"kind": "Pod",
		"metadata": {"name": "myapp-pod"},
		"spec": {
			"securityContext": {"windowsOptions": {"hostProcess": true}},
			"containers": [
				{
					"name": "myapp",
					"image": "busybox:1.28",
					"command": ["sh", "-c", "echo The app is running! && sleep 3600"],
				},
				{
					"name": "myapp-with-hostProcess",
					"image": "busybox:1.28",
					"command": ["sh", "-c", "echo The app is running! && sleep 3600"],
					"securityContext": {"windowsOptions": {"hostProcess": true}},
				},
			],
		},
	}
	deny_host_process == {
		"baseline level: pod in Pod/myapp-pod uses hostProcess",
		"baseline level: container myapp-with-hostProcess in Pod/myapp-pod uses hostProcess",
	} with input as pod
}

test_deny_host_process if {
	pod := {
		"kind": "Pod",
		"metadata": {
			"name": "myapp-pod",
			"labels": {"allowHostProcess": true},
		},
		"spec": {
			"securityContext": {"windowsOptions": {"hostProcess": true}},
			"containers": [{
				"name": "myapp-with-hostProcess",
				"image": "busybox:1.28",
				"command": ["sh", "-c", "echo The app is running! && sleep 3600"],
				"securityContext": {"windowsOptions": {"hostProcess": true}},
			}],
		},
	}
	count(deny_host_process) == 0 with input as pod
}
