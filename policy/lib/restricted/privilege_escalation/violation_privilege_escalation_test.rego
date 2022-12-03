package lib.restricted.privilege_escalation

import future.keywords

test_violation_privilege_escalation if {
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
	violation_privilege_escalation == {
		"restricted level: container myapp in Pod/myapp-pod allows privilege escalation",
		"restricted level: container allowed-myapp in Pod/myapp-pod allows privilege escalation",
	} with input as pod
}

test_violation_privilege_escalation if {
	pod := {
		"kind": "Pod",
		"metadata": {"name": "myapp-pod"},
		"spec": {
			"os": {"name": "windows"},
			"containers": [{
				"name": "myapp",
				"image": "busybox:1.28",
				"command": ["sh", "-c", "echo The app is running! && sleep 3600"],
			}],
		},
	}
	count(violation_privilege_escalation) == 0 with input as pod
}

test_violation_privilege_escalation if {
	pod := {
		"kind": "Pod",
		"metadata": {
			"name": "myapp-pod",
			"labels": {"allowPrivilegeEscalation": true},
		},
		"spec": {"containers": [{
			"name": "allowed-myapp",
			"image": "busybox:1.28",
			"command": ["sh", "-c", "echo The app is running! && sleep 3600"],
			"securityContext": {"allowPrivilegeEscalation": true},
		}]},
	}
	count(violation_privilege_escalation) == 0 with input as pod
}
