package main

test_deny_privilege_escalation {
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
				"name": "allowed-myapp",
				"image": "busybox:1.28",
				"command": ["sh", "-c", "echo The app is running! && sleep 3600"],
				"securityContext": {"allowPrivilegeEscalation": true},
			},
			{
				"name": "disallowed-myapp",
				"image": "busybox:1.28",
				"command": ["sh", "-c", "echo The app is running! && sleep 3600"],
				"securityContext": {"allowPrivilegeEscalation": false},
			},
		]},
	}
	deny_privilege_escalation == {
		"container myapp in Pod/myapp-pod allows privilege escalation",
		"container allowed-myapp in Pod/myapp-pod allows privilege escalation",
	} with input as pod
}
