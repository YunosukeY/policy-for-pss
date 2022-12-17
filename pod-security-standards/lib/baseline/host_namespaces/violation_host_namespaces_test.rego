package lib.baseline.host_namespaces

import future.keywords

test_violation_host_namespaces if {
	pod := {
		"kind": "Pod",
		"metadata": {"name": "myapp-pod"},
	}
	count(violation_host_namespaces) == 0 with input as pod
}

test_violation_host_namespaces if {
	pod := {
		"kind": "Pod",
		"metadata": {"name": "myapp-pod"},
		"spec": {"hostNetwork": true, "hostPID": true, "hostIPC": true},
	}
	violation_host_namespaces == {
		"baseline level: pod in Pod/myapp-pod uses hostNetWork",
		"baseline level: pod in Pod/myapp-pod uses hostPID",
		"baseline level: pod in Pod/myapp-pod uses hostIPC",
	} with input as pod
}

test_violation_host_namespaces if {
	pod := {
		"kind": "Pod",
		"metadata": {
			"name": "myapp-pod",
			"labels": {"allowHostNamespace": true},
		},
		"spec": {"hostNetwork": true, "hostPID": true, "hostIPC": true},
	}
	count(violation_host_namespaces) == 0 with input as pod
}
