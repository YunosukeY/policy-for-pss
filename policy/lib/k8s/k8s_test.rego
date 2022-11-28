package lib.k8s

test_is_pod {
	is_pod({"kind": "Pod"})
	not is_pod({"kind": "Deployment"})
	not is_pod({"kind": "CrobJob"})
}

test_is_workload_resource {
	not is_workload_resources({"kind": "Pod"})
	is_workload_resources({"kind": "Deployment"})
	not is_workload_resources({"kind": "CronJob"})
}

test_is_cron_job {
	not is_cron_job({"kind": "Pod"})
	not is_cron_job({"kind": "Deployment"})
	is_cron_job({"kind": "CronJob"})
}

test_pods {
	p := {"kind": "Pod"}
	pod(p) == p

	deployment := {
		"kind": "Deployment",
		"spec": {"template": {"spec": {}}},
	}
	pod(deployment) == deployment.spec.template

	cronjob := {
		"kind": "CronJob",
		"spec": {"jobTemplate": {"spec": {"template": {"spec": {}}}}},
	}
	pod(cronjob) == cronjob.spec.jobTemplate.spec.template
}

test_containers {
	p1 := {
		"kind": "Pod",
		"spec": {
			"containers": [{
				"name": "myapp-container",
				"image": "busybox:1.28",
				"command": ["sh", "-c", "echo The app is running! && sleep 3600"],
			}],
			"initContainers": [
				{
					"name": "init-myservice",
					"image": "busybox:1.28",
					"command": ["sh", "-c", "until nslookup myservice.$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace).svc.cluster.local; do echo waiting for myservice; sleep 2; done"],
				},
				{
					"name": "init-mydb",
					"image": "busybox:1.28",
					"command": ["sh", "-c", "until nslookup mydb.$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace).svc.cluster.local; do echo waiting for mydb; sleep 2; done"],
				},
			],
		},
	}
	containers(p1) == array.concat(p1.spec.containers, p1.spec.initContainers)
}
