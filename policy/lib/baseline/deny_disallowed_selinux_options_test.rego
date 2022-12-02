package lib.baseline

import future.keywords

test_deny_disallowed_selinux_options if {
	pod := {
		"kind": "Pod",
		"metadata": {"name": "myapp-pod"},
		"spec": {
			"securityContext": {"seLinuxOptions": {"type": "foo", "user": "bar", "role": "baz"}},
			"containers": [{
				"name": "myapp",
				"image": "busybox:1.28",
				"command": ["sh", "-c", "echo The app is running! && sleep 3600"],
				"securityContext": {"seLinuxOptions": {"type": "foo", "user": "bar", "role": "baz"}},
			}],
		},
	}
	deny_disallowed_selinux_options == {
		"pod in Pod/myapp-pod uses disallowed SELinux option type: foo",
		"container myapp in Pod/myapp-pod uses disallowed SELinux option type: foo",
		"pod in Pod/myapp-pod uses disallowed SELinux option user: bar",
		"container myapp in Pod/myapp-pod uses disallowed SELinux option user: bar",
		"pod in Pod/myapp-pod uses disallowed SELinux option role: baz",
		"container myapp in Pod/myapp-pod uses disallowed SELinux option role: baz",
	} with input as pod
}

test_deny_disallowed_selinux_options if {
	pod := {
		"kind": "Pod",
		"metadata": {"name": "myapp-pod"},
		"spec": {
			"securityContext": {"seLinuxOptions": {"type": "container_t", "user": "", "role": ""}},
			"containers": [{
				"name": "myapp",
				"image": "busybox:1.28",
				"command": ["sh", "-c", "echo The app is running! && sleep 3600"],
				"securityContext": {"seLinuxOptions": {"type": "container_t", "user": "", "role": ""}},
			}],
		},
	}
	count(deny_disallowed_selinux_options) == 0 with input as pod
}

test_deny_disallowed_selinux_options if {
	pod := {
		"kind": "Pod",
		"metadata": {"name": "myapp-pod"},
		"spec": {"containers": [{
			"name": "myapp",
			"image": "busybox:1.28",
			"command": ["sh", "-c", "echo The app is running! && sleep 3600"],
		}]},
	}
	count(deny_disallowed_selinux_options) == 0 with input as pod
}

test_deny_disallowed_selinux_options if {
	pod := {
		"kind": "Pod",
		"metadata": {
			"name": "myapp-pod",
			"labels": {"allowAllSeLinuxOptions": true},
		},
		"spec": {
			"securityContext": {"seLinuxOptions": {"type": "foo", "user": "bar", "role": "baz"}},
			"containers": [{
				"name": "myapp",
				"image": "busybox:1.28",
				"command": ["sh", "-c", "echo The app is running! && sleep 3600"],
				"securityContext": {"seLinuxOptions": {"type": "foo", "user": "bar", "role": "baz"}},
			}],
		},
	}
	count(deny_disallowed_selinux_options) == 0 with input as pod
}
