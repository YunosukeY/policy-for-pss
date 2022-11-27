package main

test_deny_privileged {
	p1 := {
		"kind": "Pod",
		"metadata": {"name": "myapp-pod"},
		"spec": {"containers": [
			{
				"name": "myapp",
				"image": "busybox:1.28",
				"command": ["sh", "-c", "echo The app is running! && sleep 3600"],
			},
			{
				"name": "privileged-myapp",
				"image": "busybox:1.28",
				"command": ["sh", "-c", "echo The app is running! && sleep 3600"],
				"securityContext": {"privileged": true},
			},
		]},
	}
	deny_privileged == {"container privileged-myapp in Pod/myapp-pod is privileged"} with input as p1
}
