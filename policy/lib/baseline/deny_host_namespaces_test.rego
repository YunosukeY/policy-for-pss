package lib.baseline

import future.keywords

test_deny_host_namespaces if {
	pod := {
		"kind": "Pod",
		"metadata": {"name": "myapp-pod"},
	}
	count(deny_host_namespaces) == 0 with input as pod
}

test_deny_host_namespaces if {
	pod := {
		"kind": "Pod",
		"metadata": {"name": "myapp-pod"},
		"spec": {"hostNetwork": true, "hostPID": true, "hostIPC": true},
	}
	deny_host_namespaces == {
		"pod in Pod/myapp-pod uses hostNetWork",
		"pod in Pod/myapp-pod uses hostPID",
		"pod in Pod/myapp-pod uses hostIPC",
	} with input as pod
}

test_deny_host_namespaces if {
	pod := {
		"kind": "Pod",
		"metadata": {
			"name": "myapp-pod",
			"labels": {"allowHostNamespace": true},
		},
		"spec": {"hostNetwork": true, "hostPID": true, "hostIPC": true},
	}
	count(deny_host_namespaces) == 0 with input as pod
}
