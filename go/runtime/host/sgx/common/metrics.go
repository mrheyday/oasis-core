package common

import (
	"sync"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/metrics"
	"github.com/oasisprotocol/oasis-core/go/runtime/bundle/component"
)

const (
	// labelRuntime is the label for the runtime identifier.
	labelRuntime = "runtime"
	// labelKind is the label for the TEE kind.
	labelKind = "kind"
)

var (
	// Number of TEE attestations performed.
	teeAttestationsPerformed = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "oasis_tee_attestations_performed",
			Help: "Number of TEE attestations performed.",
		},
		[]string{labelRuntime, labelKind},
	)

	// Number of successful TEE attestations.
	teeAttestationsSuccessful = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "oasis_tee_attestations_successful",
			Help: "Number of successful TEE attestations.",
		},
		[]string{labelRuntime, labelKind},
	)

	// Number of failed TEE attestations.
	teeAttestationsFailed = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "oasis_tee_attestations_failed",
			Help: "Number of failed TEE attestations.",
		},
		[]string{labelRuntime, labelKind},
	)

	teeCollectors = []prometheus.Collector{
		teeAttestationsPerformed,
		teeAttestationsSuccessful,
		teeAttestationsFailed,
	}

	metricsOnce sync.Once
)

// UpdateAttestationMetrics updates the attestation metrics if metrics are enabled.
func UpdateAttestationMetrics(runtimeID common.Namespace, kind component.TEEKind, err error) {
	if !metrics.Enabled() {
		return
	}

	runtime := runtimeID.String()
	kindStr := kind.String()

	teeAttestationsPerformed.With(prometheus.Labels{labelRuntime: runtime, labelKind: kindStr}).Inc()
	if err != nil {
		teeAttestationsFailed.With(prometheus.Labels{labelRuntime: runtime, labelKind: kindStr}).Inc()
	} else {
		teeAttestationsSuccessful.With(prometheus.Labels{labelRuntime: runtime, labelKind: kindStr}).Inc()
	}
}

// InitMetrics registers the metrics collectors if metrics are enabled.
func InitMetrics() {
	if !metrics.Enabled() {
		return
	}

	metricsOnce.Do(func() {
		prometheus.MustRegister(teeCollectors...)
	})
}
