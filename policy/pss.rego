package main

import data.lib.baseline
import data.lib.restricted.privilege_escalation
import data.lib.restricted.restricted_capabilities
import data.lib.restricted.restricted_seccomp_types
import data.lib.restricted.run_as_root
import data.lib.restricted.run_as_root_user
import data.lib.restricted.volume_types
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
	some msg in volume_types.violation_disallowed_volume_types
}

violation contains msg if {
	some msg in privilege_escalation.violation_privilege_escalation
}

violation contains msg if {
	some msg in run_as_root.violation_run_as_root
}

violation contains msg if {
	some msg in run_as_root_user.violation_run_as_root_user
}

violation contains msg if {
	some msg in restricted_seccomp_types.violation_disallowed_seccomp_types
}

violation contains msg if {
	some msg in restricted_capabilities.violation_disallowed_capabilities
}
