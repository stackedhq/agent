package executor

import (
	"fmt"
	"sort"

	"github.com/stackedapp/stacked/agent/internal/client"
	"github.com/stackedapp/stacked/agent/internal/opschema"
)

func typedPayload[T opschema.Payload](op client.Operation) (T, error) {
	var zero T
	p, err := op.ValidatePayload()
	if err != nil {
		return zero, err
	}
	t, ok := p.(T)
	if !ok {
		return zero, fmt.Errorf("internal: payload type %T does not match %T", p, zero)
	}
	return t, nil
}

func volumeMountsFrom(p opschema.ServiceDeploy) []volumeMount {
	out := make([]volumeMount, 0, len(p.Volumes))
	for _, v := range p.Volumes {
		out = append(out, volumeMount{
			HostPath:      v.HostPath,
			ContainerPath: v.ContainerPath,
			ReadOnly:      v.ReadOnly,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].ContainerPath < out[j].ContainerPath
	})
	return out
}

func resourceLimitsFrom(p opschema.ServiceDeploy) resourceLimits {
	l := p.Limits()
	return resourceLimits{
		cpuMillicores: l.CPUMillicores,
		memoryMB:      l.MemoryMB,
		restartPolicy: l.RestartPolicy,
	}
}

func cachedDomainsFrom(domains []opschema.Domain) []cachedDomain {
	out := make([]cachedDomain, 0, len(domains))
	for _, d := range domains {
		out = append(out, cachedDomain{
			Domain:               d.Domain,
			ServiceID:            d.ServiceID,
			Port:                 d.Port,
			Host:                 d.Host,
			Scheme:               d.Scheme,
			Path:                 d.Path,
			StripPrefix:          d.StripPrefix,
			OnDemandTLS:          d.OnDemandTLS,
			AuthGateMode:         d.AuthGateMode,
			AuthGateUsername:     d.AuthGateUsername,
			AuthGatePasswordHash: d.AuthGatePasswordHash,
			ServiceName:          d.ServiceName,
		})
	}
	return out
}
