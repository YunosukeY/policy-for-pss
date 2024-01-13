package lib.baseline.privileged

import rego.v1

test_violation_privileged if {
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
				"name": "privileged-myapp",
				"image": "busybox:1.28",
				"command": ["sh", "-c", "echo The app is running! && sleep 3600"],
				"securityContext": {"privileged": true},
			},
		]},
	}
	violation_privileged == {"baseline level: container privileged-myapp in Pod/myapp-pod is privileged"} with input as pod
}

test_violation_privileged if {
	pod := {
		"kind": "Pod",
		"metadata": {
			"name": "myapp-pod",
			"labels": {"allowPrivileged": true},
		},
		"spec": {"containers": [{
			"name": "privileged-myapp",
			"image": "busybox:1.28",
			"command": ["sh", "-c", "echo The app is running! && sleep 3600"],
			"securityContext": {"privileged": true},
		}]},
	}
	count(violation_privileged) == 0 with input as pod
}
