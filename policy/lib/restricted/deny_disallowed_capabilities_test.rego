package lib.restricted

test_deny_too_many_capabilities {
	pod := {
		"kind": "Pod",
		"metadata": {"name": "myapp-pod"},
		"spec": {"containers": [
			{
				"name": "not-dropped-myapp",
				"image": "busybox:1.28",
				"command": ["sh", "-c", "echo The app is running! && sleep 3600"],
			},
			{
				"name": "all-dropped-myapp",
				"image": "busybox:1.28",
				"command": ["sh", "-c", "echo The app is running! && sleep 3600"],
				"securityContext": {"capabilities": {"drop": ["ALL"]}},
			},
			{
				"name": "all-dropped-myapp2",
				"image": "busybox:1.28",
				"command": ["sh", "-c", "echo The app is running! && sleep 3600"],
				"securityContext": {"capabilities": {"drop": ["ALL", "AUDIT_WRITE"]}},
			},
			{
				"name": "all-dropped-myapp",
				"image": "busybox:1.28",
				"command": ["sh", "-c", "echo The app is running! && sleep 3600"],
				"securityContext": {"capabilities": {"drop": ["ALL"], "add": ["NET_BIND_SERVICE"]}},
			},
			{
				"name": "allowed-capability-myapp",
				"image": "busybox:1.28",
				"command": ["sh", "-c", "echo The app is running! && sleep 3600"],
				"securityContext": {"capabilities": {"drop": ["ALL"], "add": ["NET_BIND_SERVICE"]}},
			},
			{
				"name": "disallowed-capability-myapp",
				"image": "busybox:1.28",
				"command": ["sh", "-c", "echo The app is running! && sleep 3600"],
				"securityContext": {"capabilities": {"drop": ["ALL"], "add": ["NET_BIND_SERVICE", "AUDIT_WRITE"]}},
			},
		]},
	}
	deny_disallowed_capabilities == {
		"container not-dropped-myapp in Pod/myapp-pod doesn't drop \"ALL\" capability",
		"container disallowed-capability-myapp in Pod/myapp-pod has disallowed capabilities",
	} with input as pod
}
