package lib.baseline

import future.keywords

test_violation_host_path if {
	pod := {
		"kind": "Pod",
		"metadata": {"name": "myapp-pod"},
		"spec": {"volumes": [{
			"name": "test-volume",
			"hostPath": {
				"path": "/data",
				"type": "Directory",
			},
		}]},
	}
	violation_host_path == {"baseline level: volume test-volume in Pod/myapp-pod uses hostPath"} with input as pod
}

test_violation_host_path if {
	pod := {
		"kind": "Pod",
		"metadata": {"name": "myapp-pod"},
		"spec": {"volumes": []},
	}
	count(violation_host_path) == 0 with input as pod
}

test_violation_host_path if {
	pod := {
		"kind": "Pod",
		"metadata": {"name": "myapp-pod"},
		"spec": {"volumes": [{
			"name": "cache-volume",
			"emptyDir": {},
		}]},
	}
	count(violation_host_path) == 0 with input as pod
}

test_violation_host_path if {
	pod := {
		"kind": "Pod",
		"metadata": {
			"name": "myapp-pod",
			"labels": {"allowHostPath": true},
		},
		"spec": {"volumes": [{
			"name": "test-volume",
			"hostPath": {
				"path": "/data",
				"type": "Directory",
			},
		}]},
	}
	count(violation_host_path) == 0 with input as pod
}
