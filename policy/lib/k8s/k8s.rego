package lib.k8s

workload_resources := [
	"Deployment",
	"ReplicaSet",
	"StatefulSet",
	"DaemonSet",
	"Job",
	"ReplicationController",
]

is_pod(object) {
	object.kind == "Pod"
}

is_workload_resources(object) {
	object.kind == workload_resources[_]
}

is_cron_job(object) {
	object.kind == "CronJob"
}

pod(object) := p {
	is_pod(object)
	p := object
}

pod(object) := p {
	is_workload_resources(object)
	p := object.spec.template
}

pod(object) := p {
	is_cron_job(object)
	p := object.spec.jobTemplate.spec.template
}

container_keys := {
	"containers",
	"initContainers",
}

containers(object) := container {
	p := pod(object)
	container := [p.spec[k][_] | some k; container_keys[k]]
}
