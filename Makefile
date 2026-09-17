.PHONY: generate render-controller test-envtest test-kind-factorio test-kind-lifecycle verify-generated verify-runtime-assets

CANONICAL_CONTROLLER_IMAGE := ghcr.io/gobha-me/arcadectl-controller@sha256:0000000000000000000000000000000000000000000000000000000000000000

generate:
	go tool controller-gen object:headerFile=hack/boilerplate.go.txt crd:crdVersions=v1 paths=./api/... output:crd:artifacts:config=config/crd/bases
	go tool controller-gen rbac:roleName=arcadectl-controller paths=./internal/controller/... output:rbac:artifacts:config=config/rbac
	./hack/generate-install.sh $(CANONICAL_CONTROLLER_IMAGE)

render-controller:
	@test -n "$(CONTROLLER_IMAGE)" || (echo "CONTROLLER_IMAGE=<repository@sha256:digest> is required" >&2; exit 2)
	@./hack/render-controller.sh "$(CONTROLLER_IMAGE)"

test-envtest:
	go test -tags=envtest -timeout=5m ./internal/controller

test-kind-lifecycle:
	go test -tags=lifecycletest -timeout=2m ./cmd/arcadectl-controller
	timeout --foreground 15m ./hack/test-kind-lifecycle.sh

test-kind-factorio:
	go test -timeout=2m ./cmd/arcadectl-controller
	timeout --foreground 25m ./hack/test-kind-factorio.sh

verify-generated:
	./hack/verify-generated.sh

verify-runtime-assets:
	./hack/verify-runtime-assets.sh
