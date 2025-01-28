// Copyright Sauce Labs Inc., all rights reserved.

package packetdrop

import (
	"github.com/saucelabs/forwarder/utils/compose"
)

type service compose.Service

const (
	Image       = "e2e-udp"
	ServiceName = "udp"
)

func Service() *service {
	return &service{
		Name:        ServiceName,
		Image:       Image,
		Environment: map[string]string{},
		Privileged:  true,
		Network:     map[string]compose.ServiceNetwork{},
	}
}

func (s *service) Service() *compose.Service {
	return (*compose.Service)(s)
}
