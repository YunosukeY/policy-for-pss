package main

import data.lib.baseline
import data.lib.restricted
import future.keywords

# Baseline

violation contains msg if {
	some msg in baseline.violation_host_process
}

violation contains msg if {
	some msg in baseline.violation_host_namespaces
}

violation contains msg if {
	some msg in baseline.violation_privileged
}

violation contains msg if {
	some msg in baseline.violation_disallowed_capabilities
}

violation contains msg if {
	some msg in baseline.violation_host_path
}

violation contains msg if {
	some msg in baseline.violation_host_port
}

violation contains msg if {
	some msg in baseline.violation_disallowed_app_armor_profile
}

violation contains msg if {
	some msg in baseline.violation_disallowed_selinux_options
}

violation contains msg if {
	some msg in baseline.violation_unmasked_proc_mount
}

violation contains msg if {
	some msg in baseline.violation_disallowed_seccomp_types
}

violation contains msg if {
	some msg in baseline.violation_disallowed_sysctls
}

# Restricted

violation contains msg if {
	some msg in restricted.violation_disallowed_volume_types
}

violation contains msg if {
	some msg in restricted.violation_privilege_escalation
}

violation contains msg if {
	some msg in restricted.violation_run_as_root
}

violation contains msg if {
	some msg in restricted.violation_run_as_root_user
}

violation contains msg if {
	some msg in restricted.violation_disallowed_seccomp_types
}

violation contains msg if {
	some msg in restricted.violation_disallowed_capabilities
}
