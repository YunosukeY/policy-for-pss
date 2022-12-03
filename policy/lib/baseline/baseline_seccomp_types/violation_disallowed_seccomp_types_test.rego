package lib.baseline.baseline_seccomp_types

import future.keywords

test_violation_disallowed_seccomp_types if {
	pod := {
		"kind": "Pod",
		"metadata": {"name": "myapp-pod"},
		"spec": {
			"securityContext": {"seccompProfile": {"type": "Unconfined"}},
			"containers": [{
				"name": "myapp",
				"image": "busybox:1.28",
				"command": ["sh", "-c", "echo The app is running! && sleep 3600"],
				"securityContext": {"seccompProfile": {"type": "Unconfined"}},
			}],
		},
	}
	violation_disallowed_seccomp_types == {
		"baseline level: pod in Pod/myapp-pod uses disallowed seccompProfile type: Unconfined",
		"baseline level: container myapp in Pod/myapp-pod uses disallowed seccompProfile type: Unconfined",
	} with input as pod
}

test_violation_disallowed_seccomp_types if {
	pod := {
		"kind": "Pod",
		"metadata": {"name": "myapp-pod"},
		"spec": {
			"securityContext": {"seccompProfile": {"type": "RuntimeDefault"}},
			"containers": [{
				"name": "myapp",
				"image": "busybox:1.28",
				"command": ["sh", "-c", "echo The app is running! && sleep 3600"],
				"securityContext": {"seccompProfile": {"type": "RuntimeDefault"}},
			}],
		},
	}
	count(violation_disallowed_seccomp_types) == 0 with input as pod
}

test_violation_disallowed_seccomp_types if {
	pod := {
		"kind": "Pod",
		"metadata": {"name": "myapp-pod"},
		"spec": {"containers": [{
			"name": "myapp",
			"image": "busybox:1.28",
			"command": ["sh", "-c", "echo The app is running! && sleep 3600"],
		}]},
	}
	count(violation_disallowed_seccomp_types) == 0 with input as pod
}

test_violation_disallowed_seccomp_types if {
	pod := {
		"kind": "Pod",
		"metadata": {
			"name": "myapp-pod",
			"labels": {"allowPrivilegedLevelSeccompTypes": true},
		},
		"spec": {
			"securityContext": {"seccompProfile": {"type": "Unconfined"}},
			"containers": [{
				"name": "myapp",
				"image": "busybox:1.28",
				"command": ["sh", "-c", "echo The app is running! && sleep 3600"],
				"securityContext": {"seccompProfile": {"type": "Unconfined"}},
			}],
		},
	}
	count(violation_disallowed_seccomp_types) == 0 with input as pod
}
