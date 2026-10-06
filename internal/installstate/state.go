// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

// Package installstate records public installation ownership and mutation
// intent. A namespace annotation is deliberately used instead of a ConfigMap:
// game controllers can modify ConfigMaps, but cannot write Namespace objects.
// This is an administrator journal, not a grant of Kubernetes authority. The
// engine must independently prove resource semantics and runtime safety.
package installstate

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"slices"
	"strings"

	"github.com/gobha-me/arcadectl/internal/adminauth"
	"github.com/gobha-me/arcadectl/internal/canonicaljson"
	"github.com/gobha-me/arcadectl/internal/installrender"
	"k8s.io/apimachinery/pkg/types"
)

const (
	Version             = "v1"
	Annotation          = "arcade.gobha.me/installation-state"
	BootstrapAnnotation = "arcade.gobha.me/installation-bootstrap"
	MutationAnnotation  = "arcade.gobha.me/installation-mutation"
	MaxBytes            = 64 * 1024
	MaxResources        = 40 // the reviewed 38 resources plus two administrator Secrets
)

var (
	ErrInvalid        = errors.New("invalid installation journal")
	ErrOwnership      = errors.New("installation ownership could not be proved")
	ErrConflict       = errors.New("installation journal changed concurrently")
	ErrOutcomeUnknown = errors.New("installation journal write outcome is unconfirmed")
	hexID             = regexp.MustCompile(`^[0-9a-f]{32}$`)
	digestID          = regexp.MustCompile(`^[0-9a-f]{64}$`)
	identityText      = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$`)
)

type Mode string

const (
	Install   Mode = "install"
	Upgrade   Mode = "upgrade"
	Rollback  Mode = "rollback"
	Uninstall Mode = "uninstall"
)

type Stage string

const (
	Preparing        Stage = "preparing"
	Quiescing        Stage = "quiescing"
	Applying         Stage = "applying"
	Verifying        Stage = "verifying"
	Complete         Stage = "complete"
	RecoveryRequired Stage = "recovery-required"
)

type Action string

const (
	Create Action = "create"
	Update Action = "update"
	Delete Action = "delete"
)

// Key is a reviewed object address. Discovery, URLs and arbitrary resource names
// must never be taken from journal bytes without a trusted-plan comparison.
type Key struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Namespace  string `json:"namespace"`
	Name       string `json:"name"`
}

func (k Key) String() string { return k.APIVersion + "/" + k.Kind + "/" + k.Namespace + "/" + k.Name }

// Resource identifies an object created by this installation. Labels, names,
// adoption, or an already-existing same-looking object are not ownership proof.
// TemplateSHA256 covers public desired templates, never Secret material.
type Resource struct {
	Key            Key                 `json:"key"`
	UID            types.UID           `json:"uid"`
	TemplateSHA256 string              `json:"templateSha256"`
	Retained       bool                `json:"retained"`
	Phase          installrender.Phase `json:"phase"`
}

// Pending is written before a Kubernetes effect. An uncertain result remains
// pending; it is never replayed with a fresh candidate or inferred from labels.
// CreateNonce identifies the exact candidate through its public annotation.
// BeforeResourceVersion is the observed CAS precondition, not a reusable lease.
type Pending struct {
	Action                Action    `json:"action"`
	Key                   Key       `json:"key"`
	CreateNonce           string    `json:"createNonce"`
	BeforeUID             types.UID `json:"beforeUid"`
	BeforeResourceVersion string    `json:"beforeResourceVersion"`
	BeforeSHA256          string    `json:"beforeSha256"`
	AfterSHA256           string    `json:"afterSha256"`
}

// Document contains only public identities. No tokens, verifier bundles, TLS
// keys, kubeconfig bytes, private filesystem paths, or raw objects belong here.
// NamespaceUID is immutable and defeats namespace deletion/recreation attacks.
type Document struct {
	Version         string     `json:"version"`
	InstallationID  string     `json:"installationId"`
	Namespace       string     `json:"namespace"`
	NamespaceUID    types.UID  `json:"namespaceUid"`
	ProfileID       string     `json:"profileId"`
	Revision        uint64     `json:"revision"`
	Mode            Mode       `json:"mode"`
	Stage           Stage      `json:"stage"`
	ActivePackage   string     `json:"activePackage"`
	PreviousPackage string     `json:"previousPackage"`
	TargetPackage   string     `json:"targetPackage"`
	Installed       bool       `json:"installed"`
	Resources       []Resource `json:"resources"`
	Pending         *Pending   `json:"pending"`
	// AdmissionRetirementRevision pins protected pre-removal evidence for this
	// exact uninstall. Omission preserves canonical bytes of legacy journals.
	// It is not permission to skip current retained-protection observations.
	AdmissionRetirementRevision uint64 `json:"admissionRetirementRevision,omitempty"`
}

func NewID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", ErrInvalid
	}
	return hex.EncodeToString(raw[:]), nil
}

// Encode derives a canonical representation without changing caller slices.
// Validation always requires sealed renderer plans, not a schema-only decoder.
func Encode(document Document, plans ...*installrender.Plan) ([]byte, error) {
	if validate(document, plans) != nil {
		return nil, ErrInvalid
	}
	body, err := json.Marshal(document)
	if err != nil || len(body) > MaxBytes {
		return nil, ErrInvalid
	}
	body, err = canonicaljson.CanonicalJSON(body)
	if err != nil {
		return nil, ErrInvalid
	}
	return body, nil
}

func Decode(body []byte, plans ...*installrender.Plan) (Document, error) {
	var document Document
	if len(body) == 0 || len(body) > MaxBytes {
		return document, ErrInvalid
	}
	canonical, err := canonicaljson.CanonicalJSON(body)
	if err != nil || !bytes.Equal(canonical, body) {
		return document, ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&document) != nil {
		return Document{}, ErrInvalid
	}
	var extra any
	if !errors.Is(decoder.Decode(&extra), io.EOF) {
		return Document{}, ErrInvalid
	}
	encoded, err := Encode(document, plans...)
	if err != nil || !bytes.Equal(encoded, body) {
		return Document{}, ErrInvalid
	}
	return document, nil
}

type contract struct {
	retained bool
	phase    installrender.Phase
}

func contracts(plans []*installrender.Plan, namespace, profile string) (map[Key]contract, map[string]bool, error) {
	if len(plans) < 1 || len(plans) > 3 {
		return nil, nil, ErrInvalid
	}
	keys := map[Key]contract{}
	digests := map[string]bool{}
	for _, plan := range plans {
		if !plan.IsTrusted() || plan.Namespace() != namespace || plan.Profile().ID != profile || digests[plan.Digest()] {
			return nil, nil, ErrInvalid
		}
		digests[plan.Digest()] = true
		for _, resource := range plan.ResourceMetadata() {
			key := Key{resource.APIVersion, resource.Kind, resource.Namespace, resource.Name}
			value := contract{resource.Retained, resource.Phase}
			if old, ok := keys[key]; ok && old != value {
				return nil, nil, ErrInvalid
			}
			keys[key] = value
		}
	}
	for _, name := range []string{adminauth.CredentialSecretName, "arcadectl-api-tls"} {
		keys[Key{"v1", "Secret", namespace, name}] = contract{true, installrender.API}
	}
	if len(keys) != MaxResources {
		return nil, nil, ErrInvalid
	}
	return keys, digests, nil
}

func validate(d Document, plans []*installrender.Plan) error {
	if d.Version != Version || !hexID.MatchString(d.InstallationID) || !installrender.ValidNamespace(d.Namespace) || !validIdentity(string(d.NamespaceUID)) || d.Revision == 0 || d.Revision > 9007199254740991 || !validMode(d.Mode) || !validStage(d.Stage) || d.Resources == nil || len(d.Resources) > MaxResources {
		return ErrInvalid
	}
	if d.AdmissionRetirementRevision != 0 && (d.Mode != Uninstall || d.AdmissionRetirementRevision >= d.Revision || d.Stage == Preparing) {
		return ErrInvalid
	}
	keys, digests, err := contracts(plans, d.Namespace, d.ProfileID)
	if err != nil || !digests[d.TargetPackage] || d.ActivePackage != "" && !digests[d.ActivePackage] || d.PreviousPackage != "" && !digests[d.PreviousPackage] || d.ActivePackage != "" && d.PreviousPackage == d.ActivePackage {
		return ErrInvalid
	}
	if d.ActivePackage == "" && (d.Mode != Install || d.Installed || d.PreviousPackage != "") {
		return ErrInvalid
	}
	if d.Stage == Complete && (d.Pending != nil || d.ActivePackage != d.TargetPackage || d.Installed != (d.Mode != Uninstall)) {
		return ErrInvalid
	}
	if d.Stage == Quiescing && d.Mode == Install {
		return ErrInvalid
	}
	var previous string
	seenUIDs := map[types.UID]bool{}
	namespacePresent := false
	for _, entry := range d.Resources {
		c, ok := keys[entry.Key]
		if !ok || entry.Retained != c.retained || entry.Phase != c.phase || !validIdentity(string(entry.UID)) || seenUIDs[entry.UID] || entry.Key.String() <= previous || !validHash(entry.Key, entry.TemplateSHA256) {
			return ErrInvalid
		}
		if entry.Key.Kind == "Namespace" && entry.UID != d.NamespaceUID {
			return ErrInvalid
		}
		if entry.Key.Kind == "Namespace" {
			namespacePresent = true
		}
		seenUIDs[entry.UID], previous = true, entry.Key.String()
	}
	if !namespacePresent {
		return ErrInvalid
	}
	if d.Stage == Complete {
		expected := MaxResources
		if !d.Installed {
			expected = 20
		} // 18 retained templates plus two Secrets
		if len(d.Resources) != expected {
			return ErrInvalid
		}
		for _, resource := range d.Resources {
			if !d.Installed && !resource.Retained {
				return ErrInvalid
			}
		}
	}
	if p := d.Pending; p != nil {
		c, ok := keys[p.Key]
		if !ok || d.Stage == Preparing || d.Stage == Complete || !hexID.MatchString(p.CreateNonce) {
			return ErrInvalid
		}
		index := slices.IndexFunc(d.Resources, func(r Resource) bool { return r.Key == p.Key })
		switch p.Action {
		case Create:
			if index >= 0 || p.BeforeUID != "" || p.BeforeResourceVersion != "" || p.BeforeSHA256 != "" || !validHash(p.Key, p.AfterSHA256) {
				return ErrInvalid
			}
		case Update, Delete:
			if index < 0 || !validIdentity(string(p.BeforeResourceVersion)) || p.BeforeUID != d.Resources[index].UID || p.BeforeSHA256 != d.Resources[index].TemplateSHA256 {
				return ErrInvalid
			}
			if p.Action == Update && !validHash(p.Key, p.AfterSHA256) || p.Action == Delete && (c.retained || p.AfterSHA256 != "") {
				return ErrInvalid
			}
		default:
			return ErrInvalid
		}
		// The namespace is the CAS anchor and is never a separate pending effect.
		if p.Key.Kind == "Namespace" {
			return ErrInvalid
		}
	}
	return nil
}

func validIdentity(value string) bool { return identityText.MatchString(value) }
func validHash(key Key, value string) bool {
	if key.Kind == "Secret" {
		return value == ""
	}
	return digestID.MatchString(value) && value != strings.Repeat("0", 64)
}
func validMode(mode Mode) bool {
	return mode == Install || mode == Upgrade || mode == Rollback || mode == Uninstall
}
func validStage(stage Stage) bool {
	return stage == Preparing || stage == Quiescing || stage == Applying || stage == Verifying || stage == Complete || stage == RecoveryRequired
}

// SortResources is a convenience for callers constructing a new document. It
// intentionally takes an explicit slice rather than mutating during encoding.
func SortResources(resources []Resource) {
	slices.SortFunc(resources, func(a, b Resource) int { return strings.Compare(a.Key.String(), b.Key.String()) })
}

func jsonCopy(source, target any) error {
	body, err := json.Marshal(source)
	if err != nil {
		return err
	}
	return json.Unmarshal(body, target)
}
