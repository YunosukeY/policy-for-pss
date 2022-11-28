package lib.baseline

test_deny_host_namespaces {
	pod := {
		"kind": "Pod",
		"metadata": {"name": "myapp-pod"},
	}
	count(deny_host_namespaces) == 0 with input as pod
}

test_deny_host_namespaces {
	pod := {
		"kind": "Pod",
		"metadata": {"name": "myapp-pod"},
		"spec": {"hostNetwork": true, "hostPID": true, "hostIPC": true},
	}
	deny_host_namespaces == {
		"pod myapp-pod in Pod/myapp-pod uses hostNetWork",
		"pod myapp-pod in Pod/myapp-pod uses hostPID",
		"pod myapp-pod in Pod/myapp-pod uses hostIPC",
	} with input as pod
}
