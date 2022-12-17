#!/usr/bin/env bash

set -eu

repo_dir="$(git rev-parse --show-toplevel)"

kind create cluster
helmfile apply -f "${repo_dir}/e2e"
kubectl apply -f "${repo_dir}/k8s/template_PodSecurityStandards.yaml"
sleep 1 # hack
kubectl apply -f "${repo_dir}/k8s/constraint_PodSecurityStandards.yaml"
kubectl create namespace test

kubectl apply -f "${repo_dir}/example/safe.yaml"
! kubectl apply -f "${repo_dir}/example/unsafe.yaml"
kubectl apply -f "${repo_dir}/example/allowed.yaml"
