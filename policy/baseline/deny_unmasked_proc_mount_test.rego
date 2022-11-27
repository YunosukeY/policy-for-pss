package main

test_deny_unmasked_proc_mount {
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
				"name": "default-myapp",
				"image": "busybox:1.28",
				"command": ["sh", "-c", "echo The app is running! && sleep 3600"],
				"securityContext": {"procMount": "Default"},
			},
			{
				"name": "unmasked-myapp",
				"image": "busybox:1.28",
				"command": ["sh", "-c", "echo The app is running! && sleep 3600"],
				"securityContext": {"procMount": "Unmasked"},
			},
		]},
	}
	deny_unmasked_proc_mount == {"container unmasked-myapp in Pod/myapp-pod doesn't mask /proc mount"} with input as pod
}
