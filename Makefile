.PHONY: generate render-api render-controller test-envtest test-kind-api test-kind-factorio test-kind-lifecycle test-kind-recovery verify-generated verify-runtime-assets

CANONICAL_CONTROLLER_IMAGE := ghcr.io/gobha-me/arcadectl-controller@sha256:0000000000000000000000000000000000000000000000000000000000000000

generate:
	go tool controller-gen object:headerFile=hack/boilerplate.go.txt crd:crdVersions=v1 paths=./api/... output:crd:artifacts:config=config/crd/bases
	go tool controller-gen rbac:roleName=arcadectl-controller paths=./internal/controller/... output:rbac:artifacts:config=config/rbac
	./hack/generate-install.sh $(CANONICAL_CONTROLLER_IMAGE)

render-controller:
	@test -n "$(CONTROLLER_IMAGE)" || (echo "CONTROLLER_IMAGE=<repository@sha256:digest> is required" >&2; exit 2)
	@./hack/render-controller.sh "$(CONTROLLER_IMAGE)"

render-api:
	@test -n "$(API_IMAGE)" || (echo "API_IMAGE=<repository@sha256:digest> is required" >&2; exit 2)
	@bash ./hack/render-api.sh "$(API_IMAGE)"

test-envtest:
	go test -tags=envtest -p 1 -timeout=5m ./api/v1alpha1 ./internal/controller ./internal/install

test-kind-api:
	GOMAXPROCS=2 GOMEMLIMIT=1GiB go test -tags=kindapi -p 1 -timeout=22m -v ./internal/install -run '^TestKindAuthenticatedAdmin$$' -count=1

test-kind-lifecycle:
	go test -tags=lifecycletest -timeout=2m ./cmd/arcadectl-controller
	timeout --foreground 15m ./hack/test-kind-lifecycle.sh

test-kind-factorio:
	go test -timeout=2m ./cmd/arcadectl-controller
	timeout --foreground 25m ./hack/test-kind-factorio.sh

test-kind-recovery:
	go test -timeout=2m ./cmd/arcadectl-controller
	timeout --foreground 90m ./hack/test-kind-recovery.sh

verify-generated:
	./hack/verify-generated.sh

verify-runtime-assets:
	./hack/verify-runtime-assets.sh
