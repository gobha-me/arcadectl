// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package admincredential

import (
	"errors"
	"reflect"
	"time"

	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/client-go/kubernetes"
)

// ErrInvalidConfiguration is deliberately fixed; configuration and transport
// errors may contain private paths, credentials or endpoint data.
var ErrInvalidConfiguration = errors.New("invalid administrator credential configuration")

// Config selects the one trusted installation namespace. It has no implicit
// default: only the administrator command supplies the canonical legacy default.
type Config struct{ Namespace string }
type InitializeOptions struct {
	OutputPath string
	Now        time.Time
	Lifetime   time.Duration
}
type RotateOptions struct {
	OutputPath             string
	Now                    time.Time
	Lifetime, PollInterval time.Duration
}
type ProbeOptions struct{ Namespace, Endpoint, CAFile, TLSServerName string }

type Workflow struct {
	cluster   ClusterAccess
	namespace string
}

// New creates a namespace-bound trusted administrator workflow. It does not
// verify installation ownership; the installer must establish that separately.
func New(client kubernetes.Interface, config Config) (*Workflow, error) {
	if nilValue(client) {
		return nil, ErrInvalidConfiguration
	}
	return NewWithAccess(clientGoAccess{client: client, namespace: config.Namespace}, config)
}

// NewWithAccess is a trusted-administrator instrumentation seam, not an
// authorization boundary. Returned object namespaces are still checked. Callers
// must enforce installation ownership and journal mutations separately.
func NewWithAccess(access ClusterAccess, config Config) (*Workflow, error) {
	if nilValue(access) || len(validation.IsDNS1123Label(config.Namespace)) != 0 {
		return nil, ErrInvalidConfiguration
	}
	return &Workflow{cluster: access, namespace: config.Namespace}, nil
}

func (w *Workflow) Namespace() string {
	if w == nil {
		return ""
	}
	return w.namespace
}

func nilValue(value any) bool {
	if value == nil {
		return true
	}
	v := reflect.ValueOf(value)
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return v.IsNil()
	}
	return false
}
