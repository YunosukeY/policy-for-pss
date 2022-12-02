package lib.baseline

import future.keywords

test_deny_disallowed_sysctls if {
	pod := {
		"kind": "Pod",
		"metadata": {"name": "myapp-pod"},
		"spec": {"securityContext": {"sysctls": [{
			"name": "kernel.shm_rmid_forced",
			"value": "0",
		}]}},
	}
	count(deny_disallowed_sysctls) == 0 with input as pod
}

test_deny_disallowed_sysctls if {
	pod := {
		"kind": "Pod",
		"metadata": {"name": "myapp-pod"},
		"spec": {"securityContext": {"sysctls": [{
			"name": "net.core.somaxconn",
			"value": "1024",
		}]}},
	}
	deny_disallowed_sysctls == {"pod in Pod/myapp-pod uses disallowed sysctl: net.core.somaxconn"} with input as pod
}

test_deny_disallowed_sysctls if {
	pod := {
		"kind": "Pod",
		"metadata": {"name": "myapp-pod"},
	}
	count(deny_disallowed_sysctls) == 0 with input as pod
}

test_deny_disallowed_sysctls if {
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
	count(deny_disallowed_sysctls) == 0 with input as pod
}
