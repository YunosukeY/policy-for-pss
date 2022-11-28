package main

import data.lib.baseline
import data.lib.restricted

# Baseline

deny[msg] {
	some msg
	baseline.deny_host_process[msg]
}

deny[msg] {
	some msg
	baseline.deny_host_namespaces[msg]
}

deny[msg] {
	some msg
	baseline.deny_privileged[msg]
}

deny[msg] {
	some msg
	baseline.deny_disallowed_capabilities[msg]
}

deny[msg] {
	some msg
	baseline.deny_unmasked_proc_mount[msg]
}

# Restricted

deny[msg] {
	some msg
	restricted.deny_privilege_escalation[msg]
}

deny[msg] {
	some msg
	restricted.deny_run_as_root[msg]
}

deny[msg] {
	some msg
	restricted.deny_disallowed_capabilities[msg]
}
