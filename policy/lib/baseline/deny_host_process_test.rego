package lib.baseline

test_deny_host_process {
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
		"pod myapp-pod in Pod/myapp-pod uses hostProcess",
		"container myapp-with-hostProcess in Pod/myapp-pod uses hostProcess",
	} with input as pod
}
