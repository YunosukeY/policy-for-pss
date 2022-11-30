package main

import data.lib.baseline
import data.lib.restricted
import future.keywords

# Baseline

deny contains msg if {
	some msg in baseline.deny_host_process
}

deny contains msg if {
	some msg in baseline.deny_host_namespaces
}

deny contains msg if {
	some msg in baseline.deny_privileged
}

deny contains msg if {
	some msg in baseline.deny_disallowed_capabilities
}

deny contains msg if {
	some msg in baseline.deny_host_path
}

deny contains msg if {
	some msg in baseline.deny_host_port
}

deny contains msg if {
	some msg in baseline.deny_disallowed_app_armor_profile
}

deny contains msg if {
	some msg in baseline.deny_unmasked_proc_mount
}

# Restricted

deny contains msg if {
	some msg in restricted.deny_privilege_escalation
}

deny contains msg if {
	some msg in restricted.deny_run_as_root
}

deny contains msg if {
	some msg in restricted.deny_disallowed_capabilities
}
