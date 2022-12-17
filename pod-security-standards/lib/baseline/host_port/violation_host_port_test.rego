package lib.baseline.host_port

import future.keywords

test_violation_host_port if {
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
	violation_host_port == {"baseline level: containerPort 8080 in container myapp in Pod/myapp-pod uses hostPort"} with input as pod
}

test_violation_host_port if {
	pod := {
		"kind": "Pod",
		"metadata": {
			"name": "myapp-pod",
			"labels": {"allowHostPort": true},
		},
		"spec": {"containers": [{
			"name": "myapp",
			"image": "busybox:1.28",
			"command": ["sh", "-c", "echo The app is running! && sleep 3600"],
			"ports": [{
				"containerPort": 8080,
				"hostPort": 8080,
			}],
		}]},
	}
	count(violation_host_port) == 0 with input as pod
}
