package lib.restricted

import future.keywords

test_deny_disallowed_seccomp_types if {
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
	deny_disallowed_seccomp_types == {
		"restricted level: pod in Pod/myapp-pod uses disallowed seccompProfile type: Unconfined",
		"restricted level: container myapp in Pod/myapp-pod uses disallowed seccompProfile type: Unconfined",
	} with input as pod
}

test_deny_disallowed_seccomp_types if {
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
	count(deny_disallowed_seccomp_types) == 0 with input as pod
}

test_deny_disallowed_seccomp_types if {
	pod := {
		"kind": "Pod",
		"metadata": {"name": "myapp-pod"},
		"spec": {"containers": [{
			"name": "myapp",
			"image": "busybox:1.28",
			"command": ["sh", "-c", "echo The app is running! && sleep 3600"],
		}]},
	}
	deny_disallowed_seccomp_types == {
		"restricted level: pod in Pod/myapp-pod must be set seccomp profile",
		"restricted level: container myapp in Pod/myapp-pod must be set seccomp profile",
	} with input as pod
}

test_deny_disallowed_seccomp_types if {
	pod := {
		"kind": "Pod",
		"metadata": {"name": "myapp-pod"},
		"spec": {
			"os": {"name": "windows"},
			"containers": [{
				"name": "myapp",
				"image": "busybox:1.28",
				"command": ["sh", "-c", "echo The app is running! && sleep 3600"],
			}],
		},
	}
	count(deny_disallowed_seccomp_types) == 0 with input as pod
}

test_deny_disallowed_seccomp_types if {
	pod := {
		"kind": "Pod",
		"metadata": {"name": "myapp-pod"},
		"spec": {
			"os": {"name": "linux"},
			"containers": [{
				"name": "myapp",
				"image": "busybox:1.28",
				"command": ["sh", "-c", "echo The app is running! && sleep 3600"],
			}],
		},
	}
	deny_disallowed_seccomp_types == {
		"restricted level: pod in Pod/myapp-pod must be set seccomp profile",
		"restricted level: container myapp in Pod/myapp-pod must be set seccomp profile",
	} with input as pod
}

test_deny_disallowed_seccomp_types if {
	pod := {
		"kind": "Pod",
		"metadata": {
			"name": "myapp-pod",
			"labels": {"allowBaselineLevelSeccompTypes": true},
		},
		"spec": {"containers": [{
			"name": "myapp",
			"image": "busybox:1.28",
			"command": ["sh", "-c", "echo The app is running! && sleep 3600"],
		}]},
	}
	count(deny_disallowed_seccomp_types) == 0 with input as pod
}
