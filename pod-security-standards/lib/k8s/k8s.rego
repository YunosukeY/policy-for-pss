package lib.k8s

import future.keywords

workload_resources := {
	"Deployment",
	"ReplicaSet",
	"StatefulSet",
	"DaemonSet",
	"Job",
	"ReplicationController",
}

is_pod(object) if {
	object.kind == "Pod"
}

is_workload_resources(object) if {
	object.kind in workload_resources
}

is_cron_job(object) if {
	object.kind == "CronJob"
}

pod(object) := p if {
	is_pod(object)
	p := object
}

pod(object) := p if {
	is_workload_resources(object)
	p := object.spec.template
}

pod(object) := p if {
	is_cron_job(object)
	p := object.spec.jobTemplate.spec.template
}

container_keys := {
	"containers",
	"initContainers",
}

containers(object) := container if {
	p := pod(object)
	container := {c | some k in container_keys; some c in p.spec[k]}
}
