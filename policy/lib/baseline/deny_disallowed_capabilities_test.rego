package lib.baseline

import future.keywords

test_deny_too_many_capabilities if {
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
				"name": "restricted-myapp",
				"image": "busybox:1.28",
				"command": ["sh", "-c", "echo The app is running! && sleep 3600"],
				"securityContext": {"capabilities": {"add": ["AUDIT_WRITE"]}},
			},
			{
				"name": "expanded-myapp",
				"image": "busybox:1.28",
				"command": ["sh", "-c", "echo The app is running! && sleep 3600"],
				"securityContext": {"capabilities": {"add": ["NET_ADMIN"]}},
			},
			{
				"name": "expanded-myapp2",
				"image": "busybox:1.28",
				"command": ["sh", "-c", "echo The app is running! && sleep 3600"],
				"securityContext": {"capabilities": {"add": ["AUDIT_WRITE", "NET_ADMIN"]}},
			},
		]},
	}
	deny_disallowed_capabilities == {
		"container expanded-myapp in Pod/myapp-pod has disallowed capabilities",
		"container expanded-myapp2 in Pod/myapp-pod has disallowed capabilities",
	} with input as pod
}
