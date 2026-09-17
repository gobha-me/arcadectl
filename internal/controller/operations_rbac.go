// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package controller

// Operation RBAC is declared before workers exist so the durable API contract
// is reviewable. It permits observation and status reporting only. Repository
// Secret reads and worker/PVC authority are added, narrowly, with the worker
// implementations that require them.
// +kubebuilder:rbac:groups=arcade.gobha.me,resources=gamebackups;gamerestores,verbs=get;list;watch,namespace=arcadectl-system
// +kubebuilder:rbac:groups=arcade.gobha.me,resources=gamebackups/status;gamerestores/status,verbs=get;update;patch,namespace=arcadectl-system
