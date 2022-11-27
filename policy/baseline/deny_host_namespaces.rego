package main

import data.lib.k8s

deny_host_namespaces[msg] {
	pod := k8s.pod(input)
	pod.spec.hostNetwork
	msg := sprintf("pod %s in %s/%s uses hostNetWork", [pod.metadata.name, input.kind, input.metadata.name])
}

deny_host_namespaces[msg] {
	pod := k8s.pod(input)
	pod.spec.hostPID
	msg := sprintf("pod %s in %s/%s uses hostPID", [pod.metadata.name, input.kind, input.metadata.name])
}

deny_host_namespaces[msg] {
	pod := k8s.pod(input)
	pod.spec.hostIPC
	msg := sprintf("pod %s in %s/%s uses hostIPC", [pod.metadata.name, input.kind, input.metadata.name])
}
