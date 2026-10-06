.PHONY: generate generate-openapi generate-cli verify-cli render-api render-controller test-envtest test-kind-api test-kind-install-auth test-kind-factorio test-kind-lifecycle test-kind-recovery verify-generated verify-openapi verify-runtime-assets

CANONICAL_CONTROLLER_IMAGE := ghcr.io/gobha-me/arcadectl-controller@sha256:0000000000000000000000000000000000000000000000000000000000000000

generate:
	go tool controller-gen object:headerFile=hack/boilerplate.go.txt crd:crdVersions=v1 paths=./api/... output:crd:artifacts:config=config/crd/bases
	go tool controller-gen rbac:roleName=arcadectl-controller paths=./internal/controller/... output:rbac:artifacts:config=config/rbac
	./hack/generate-install.sh $(CANONICAL_CONTROLLER_IMAGE)
	$(MAKE) generate-openapi
	$(MAKE) generate-cli

generate-cli:
	GOMAXPROCS=2 GOMEMLIMIT=1GiB go run ./cmd/arcadectl-cli-docs

verify-cli:
	GOMAXPROCS=2 GOMEMLIMIT=1GiB go run ./cmd/arcadectl-cli-docs --check

generate-openapi:
	GOMAXPROCS=2 GOMEMLIMIT=1GiB bash ./hack/generate-openapi.sh

verify-openapi:
	GOMAXPROCS=2 GOMEMLIMIT=1GiB bash ./hack/verify-openapi.sh

render-controller:
	@test -n "$(CONTROLLER_IMAGE)" || (echo "CONTROLLER_IMAGE=<repository@sha256:digest> is required" >&2; exit 2)
	@./hack/render-controller.sh "$(CONTROLLER_IMAGE)"

render-api:
	@test -n "$(API_IMAGE)" || (echo "API_IMAGE=<repository@sha256:digest> is required" >&2; exit 2)
	@bash ./hack/render-api.sh "$(API_IMAGE)"

test-envtest:
	# This also runs every ordinary test in these packages. Keep that coverage;
	# the installer suite must not consume the budget before native profiles start.
	# Native API-server evidence must execute, not reuse a prior test-result cache.
	go test -tags=envtest -p 1 -timeout=20m -count=1 ./api/v1alpha1 ./internal/controller ./internal/install ./internal/installcontract ./internal/installengine

test-kind-api:
	GOMAXPROCS=2 GOMEMLIMIT=1GiB go test -tags=kindapi -p 1 -timeout=35m -v ./internal/install -run '^TestKindAuthenticatedAdmin$$' -count=1

test-kind-install-auth:
	GOMAXPROCS=2 GOMEMLIMIT=1GiB go test -tags=kindinstall -p 1 -timeout=48m -v ./internal/installengine -run '^TestKindTargetAuthenticatedNativeKubelet$$' -count=1

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
