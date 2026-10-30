.PHONY: generate generate-openapi generate-cli verify-cli verify-doc-links render-api render-controller test-envtest test-envtest-part test-kind-api test-kind-install-auth test-kind-install-admission test-kind-install-admission-v3 test-kind-install-baseline test-kind-install-gc test-kind-install-precontroller test-kind-install-binary test-kind-factorio test-kind-lifecycle test-kind-recovery verify-generated verify-openapi verify-runtime-assets

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
	# Complete five-package coverage, including every ordinary engine tree WITH
	# envtest enabled. Compiled discovery includes new tests, examples and fuzz seeds.
	# Run all partitions sequentially here; CI runs each on a separate hosted worker.
	# Fresh count=1 evidence and the finite 30m process caps are unchanged.
	GOMAXPROCS=2 GOMEMLIMIT=1GiB bash ./hack/test-envtest-part.sh --all

test-envtest-part:
	@test -n "$(ENVTEST_PART)" || (echo "ENVTEST_PART=base-packages or 0..31 is required" >&2; exit 2)
	GOMAXPROCS=2 GOMEMLIMIT=1GiB bash ./hack/test-envtest-part.sh "$(ENVTEST_PART)"

test-kind-api:
	GOMAXPROCS=2 GOMEMLIMIT=1GiB go test -tags=kindapi -p 1 -timeout=35m -v ./internal/install -run '^TestKind(AuthenticatedAdmin|APIRequestDiagnostic.*)$$' -count=1

test-kind-install-auth:
	GOMAXPROCS=2 GOMEMLIMIT=1GiB go test -tags=kindinstall -p 1 -timeout=48m -v ./internal/installengine -run '^(TestKind(TargetAuthenticatedNativeKubelet|AdmissionFixturesWarmControllers)|TestWarmNativeLeaderClockDomainsRemainBounded)$$' -count=1

# Each full production-provider run owns one disposable cluster. CI runs the
# four closed profile/mode combinations on separate runners; local runs remain
# serial. Invalid or empty selections must fail before any cluster creation.
test-kind-install-admission:
	@test "$(INSTALL_ADMISSION_PROFILE)" = 135 || test "$(INSTALL_ADMISSION_PROFILE)" = 137
	@test "$(INSTALL_ADMISSION_MODE)" = cold || test "$(INSTALL_ADMISSION_MODE)" = warm
	GOMAXPROCS=2 GOMEMLIMIT=1GiB go test -tags=kindinstall -p 1 -timeout=45m -v ./internal/installengine -run '^TestKindAdmissionEffectiveFullMatrix$$/^kubernetes-1[.]$(if $(filter 135,$(INSTALL_ADMISSION_PROFILE)),35[.]8,37[.]0)$$/^$(INSTALL_ADMISSION_MODE)$$' -count=1

# Independent baseline-active v3 matrix; historical v2 remains required above.
test-kind-install-admission-v3:
	@test "$(INSTALL_ADMISSION_PROFILE)" = 135 || test "$(INSTALL_ADMISSION_PROFILE)" = 137
	@test "$(INSTALL_ADMISSION_MODE)" = cold || test "$(INSTALL_ADMISSION_MODE)" = warm
	GOMAXPROCS=2 GOMEMLIMIT=1GiB go test -tags=kindinstall -p 1 -timeout=45m -v ./internal/installengine -run '^TestKindAdmissionEffectiveV3WithBaseline$$/^kubernetes-1[.]$(if $(filter 135,$(INSTALL_ADMISSION_PROFILE)),35[.]8,37[.]0)$$/^$(INSTALL_ADMISSION_MODE)$$' -count=1

# Actual controller-manager typechecking and original prerequisite effects.
# A component gate, never a substitute for full admission or binary lifecycle.
test-kind-install-baseline:
	@test "$(INSTALL_BASELINE_PROFILE)" = 135 || test "$(INSTALL_BASELINE_PROFILE)" = 137
	GOMAXPROCS=2 GOMEMLIMIT=1GiB go test -tags=kindinstall -p 1 -timeout=24m -v ./internal/installengine -run '^TestKindBaselinePrerequisiteCreateNative$$/^kubernetes-1[.]$(if $(filter 135,$(INSTALL_BASELINE_PROFILE)),35[.]8,37[.]0)$$' -count=1

# Authentic historical runtime policies plus native foreground GC on owned
# inert originals. This component proof cannot replace signed-binary lifecycle.
test-kind-install-gc:
	GOMAXPROCS=2 GOMEMLIMIT=1GiB go test -tags=kindinstall -p 1 -timeout=24m -v ./internal/installengine -run '^TestKindBaselineNativeForegroundGarbageCollection$$' -count=1

# Genuine pre-controller originals and full runtime/retained Secret barriers.
# Separate from the short prerequisite gate and full signed-binary lifecycle.
test-kind-install-precontroller:
	@test "$(INSTALL_PRECONTROLLER_PROFILE)" = 135 || test "$(INSTALL_PRECONTROLLER_PROFILE)" = 137
	GOMAXPROCS=2 GOMEMLIMIT=1GiB go test -tags=kindinstall -p 1 -timeout=35m -v ./internal/installengine -run '^TestKindBaselinePrecontrollerRuntimeNative$$/^kubernetes-1[.]$(if $(filter 135,$(INSTALL_PRECONTROLLER_PROFILE)),35[.]8,37[.]0)$$' -count=1

# Actual signed installer executable, never direct-effect fixture bootstrap.
# Both profiles prove current fresh install/retaining uninstall. The additional
# profile 137 transition proves the authentic legacy upgrade/rollback chain.
test-kind-install-binary:
	@test "$(INSTALL_BINARY_PROFILE)" = 135 || test "$(INSTALL_BINARY_PROFILE)" = 137
	@test "$(INSTALL_BINARY_MODE)" = fresh || test "$(INSTALL_BINARY_MODE)" = transition
	@test "$(INSTALL_BINARY_PROFILE)" = 137 || test "$(INSTALL_BINARY_MODE)" = fresh
	GOMAXPROCS=2 GOMEMLIMIT=1GiB go test -tags=kindinstall -p 1 -timeout=340m -v ./internal/installengine -run '^TestKindSignedInstallerBinaryLifecycle$$/^kubernetes-1[.]$(if $(filter 135,$(INSTALL_BINARY_PROFILE)),35[.]8,37[.]0)$$/^$(INSTALL_BINARY_MODE)$$' -count=1

test-kind-lifecycle:
	go test -tags=lifecycletest -timeout=2m ./cmd/arcadectl-controller
	timeout --foreground 15m ./hack/test-kind-lifecycle.sh

test-kind-factorio:
	go test -timeout=2m ./cmd/arcadectl-controller
	timeout --foreground 25m ./hack/test-kind-factorio.sh

test-kind-recovery:
	go test -timeout=2m ./cmd/arcadectl-controller
	timeout --foreground 90m ./hack/test-kind-recovery.sh

# Run the offline documentation check before invoking Go generators.
# verify-doc-links remains a standalone target for mandatory docs-scope CI.
verify-generated: verify-doc-links
	./hack/verify-generated.sh

verify-doc-links:
	python3 -B -m unittest discover -s hack -p 'test_doc_links.py'
	python3 -B hack/check-doc-links.py

verify-runtime-assets:
	./hack/verify-runtime-assets.sh
