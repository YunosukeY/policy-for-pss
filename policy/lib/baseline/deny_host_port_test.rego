package lib.baseline

import future.keywords

test_deny_host_port if {
	pod := {
		"kind": "Pod",
		"metadata": {"name": "myapp-pod"},
		"spec": {"containers": [{
			"name": "myapp",
			"image": "busybox:1.28",
			"command": ["sh", "-c", "echo The app is running! && sleep 3600"],
			"ports": [
				{
					"containerPort": 8080,
					"hostPort": 8080,
				},
				{
					"containerPort": 8081,
					"hostPort": 0,
				},
				{"containerPort": 8082},
			],
		}]},
	}
	deny_host_port == {"containerPort 8080 in container myapp in Pod/myapp-pod uses hostPort"} with input as pod
}
