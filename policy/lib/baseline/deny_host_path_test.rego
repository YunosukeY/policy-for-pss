package lib.baseline

test_deny_host_path {
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
	deny_host_path == {"volume test-volume pod myapp-pod in Pod/myapp-pod uses hostPath"} with input as pod

	pod2 := {
		"kind": "Pod",
		"metadata": {"name": "myapp-pod"},
		"spec": {"volumes": []},
	}
	count(deny_host_path) == 0 with input as pod2

	pod3 := {
		"kind": "Pod",
		"metadata": {"name": "myapp-pod"},
		"spec": {"volumes": [{
			"name": "cache-volume",
			"emptyDir": {},
		}]},
	}
	count(deny_host_path) == 0 with input as pod3
}
