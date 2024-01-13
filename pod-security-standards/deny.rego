package main

import data.lib.baseline.app_armor_profile
import data.lib.baseline.baseline_capabilities
import data.lib.baseline.baseline_seccomp_types
import data.lib.baseline.host_namespaces
import data.lib.baseline.host_path
import data.lib.baseline.host_port
import data.lib.baseline.host_process
import data.lib.baseline.privileged
import data.lib.baseline.proc_mount
import data.lib.baseline.selinux_options
import data.lib.baseline.sysctls
import data.lib.restricted.privilege_escalation
import data.lib.restricted.restricted_capabilities
import data.lib.restricted.restricted_seccomp_types
import data.lib.restricted.run_as_root
import data.lib.restricted.run_as_root_user
import data.lib.restricted.volume_types
import rego.v1

# Baseline

violation contains msg if {
	some msg in host_process.violation_host_process
}

violation contains msg if {
	some msg in host_namespaces.violation_host_namespaces
}

violation contains msg if {
	some msg in privileged.violation_privileged
}

violation contains msg if {
	some msg in baseline_capabilities.violation_disallowed_capabilities
}

violation contains msg if {
	some msg in host_path.violation_host_path
}

violation contains msg if {
	some msg in host_port.violation_host_port
}

violation contains msg if {
	some msg in app_armor_profile.violation_disallowed_app_armor_profile
}

violation contains msg if {
	some msg in selinux_options.violation_disallowed_selinux_options
}

violation contains msg if {
	some msg in proc_mount.violation_unmasked_proc_mount
}

violation contains msg if {
	some msg in baseline_seccomp_types.violation_disallowed_seccomp_types
}

violation contains msg if {
	some msg in sysctls.violation_disallowed_sysctls
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
