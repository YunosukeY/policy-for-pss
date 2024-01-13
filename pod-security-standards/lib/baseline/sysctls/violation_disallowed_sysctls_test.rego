package lib.baseline.sysctls

import rego.v1

test_violation_disallowed_sysctls if {
	pod := {
		"kind": "Pod",
		"metadata": {"name": "myapp-pod"},
		"spec": {"securityContext": {"sysctls": [{
			"name": "kernel.shm_rmid_forced",
			"value": "0",
		}]}},
	}
	count(violation_disallowed_sysctls) == 0 with input as pod
}

test_violation_disallowed_sysctls if {
	pod := {
		"kind": "Pod",
		"metadata": {"name": "myapp-pod"},
		"spec": {"securityContext": {"sysctls": [{
			"name": "net.core.somaxconn",
			"value": "1024",
		}]}},
	}
	violation_disallowed_sysctls == {"baseline level: pod in Pod/myapp-pod uses disallowed sysctl: net.core.somaxconn"} with input as pod
}

test_violation_disallowed_sysctls if {
	pod := {
		"kind": "Pod",
		"metadata": {"name": "myapp-pod"},
	}
	count(violation_disallowed_sysctls) == 0 with input as pod
}

test_violation_disallowed_sysctls if {
	pod := {
		"kind": "Pod",
		"metadata": {
			"name": "myapp-pod",
			"labels": {"allowAllSysctls": true},
		},
		"spec": {"securityContext": {"sysctls": [{
			"name": "net.core.somaxconn",
			"value": "1024",
		}]}},
	}
	count(violation_disallowed_sysctls) == 0 with input as pod
}
