package lib.baseline.selinux_options

import rego.v1

test_violation_disallowed_selinux_options if {
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
	violation_disallowed_selinux_options == {
		"baseline level: pod in Pod/myapp-pod uses disallowed SELinux option type: foo",
		"baseline level: container myapp in Pod/myapp-pod uses disallowed SELinux option type: foo",
		"baseline level: pod in Pod/myapp-pod uses disallowed SELinux option user: bar",
		"baseline level: container myapp in Pod/myapp-pod uses disallowed SELinux option user: bar",
		"baseline level: pod in Pod/myapp-pod uses disallowed SELinux option role: baz",
		"baseline level: container myapp in Pod/myapp-pod uses disallowed SELinux option role: baz",
	} with input as pod
}

test_violation_disallowed_selinux_options if {
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
	count(violation_disallowed_selinux_options) == 0 with input as pod
}

test_violation_disallowed_selinux_options if {
	pod := {
		"kind": "Pod",
		"metadata": {"name": "myapp-pod"},
		"spec": {"containers": [{
			"name": "myapp",
			"image": "busybox:1.28",
			"command": ["sh", "-c", "echo The app is running! && sleep 3600"],
		}]},
	}
	count(violation_disallowed_selinux_options) == 0 with input as pod
}

test_violation_disallowed_selinux_options if {
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
	count(violation_disallowed_selinux_options) == 0 with input as pod
}
