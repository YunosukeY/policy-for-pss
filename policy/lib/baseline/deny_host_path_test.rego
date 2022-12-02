package lib.baseline

import future.keywords

test_deny_host_path if {
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
	deny_host_path == {"volume test-volume in Pod/myapp-pod uses hostPath"} with input as pod
}

test_deny_host_path if {
	pod := {
		"kind": "Pod",
		"metadata": {"name": "myapp-pod"},
		"spec": {"volumes": []},
	}
	count(deny_host_path) == 0 with input as pod
}

test_deny_host_path if {
	pod := {
		"kind": "Pod",
		"metadata": {"name": "myapp-pod"},
		"spec": {"volumes": [{
			"name": "cache-volume",
			"emptyDir": {},
		}]},
	}
	count(deny_host_path) == 0 with input as pod
}

test_deny_host_path if {
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
	count(deny_host_path) == 0 with input as pod
}
