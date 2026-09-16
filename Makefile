.PHONY: generate verify-generated

generate:
	go tool controller-gen object:headerFile=hack/boilerplate.go.txt crd:crdVersions=v1 paths=./api/... output:crd:artifacts:config=config/crd/bases

verify-generated:
	./hack/verify-generated.sh
