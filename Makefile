.PHONY: generate verify-generated verify-runtime-assets

generate:
	go tool controller-gen object:headerFile=hack/boilerplate.go.txt crd:crdVersions=v1 paths=./api/... output:crd:artifacts:config=config/crd/bases
	go tool controller-gen rbac:roleName=arcadectl-controller paths=./internal/controller/... output:rbac:artifacts:config=config/rbac

verify-generated:
	./hack/verify-generated.sh

verify-runtime-assets:
	./hack/verify-runtime-assets.sh
