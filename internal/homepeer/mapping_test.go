//nolint:testpackage // Verify the private gateway ownership and lease transaction before router writes.
package homepeer

import (
	"context"
	"errors"
	"testing"

	"github.com/huin/goupnp/soap"
)

type gatewayFixture struct {
	internal                     uint16
	local, description, external string
	fault                        error
	added, deleted               bool
}

func (g *gatewayFixture) GetExternalIPAddressCtx(context.Context) (string, error) {
	return g.external, nil
}

func (g *gatewayFixture) GetSpecificPortMappingEntryCtx(context.Context, string, uint16, string) (uint16, string, bool, string, uint32, error) {
	return g.internal, g.local, true, g.description, mappingLease, g.fault
}

func (g *gatewayFixture) AddPortMappingCtx(_ context.Context, remote string, external uint16, protocol string, internal uint16, local string, enabled bool, description string, lease uint32) error {
	if remote != "" || external != 51821 || protocol != "UDP" || internal != 51821 || local != "192.168.1.215" || !enabled || description != mappingDescription || lease != mappingLease {
		return errors.New("unexpected mapping scope")
	}
	g.added = true
	return nil
}

func (g *gatewayFixture) DeletePortMappingCtx(context.Context, string, uint16, string) error {
	g.deleted = true
	return nil
}

func TestMappingCreatesOnlyLeasedOwnedUDPPort(t *testing.T) {
	t.Parallel()
	missing := &soap.SOAPFaultError{}
	missing.Detail.UPnPError.Errorcode = 714
	router := &gatewayFixture{fault: missing, external: "31.49.158.120"}
	mapping := &Mapping{gateway: router, port: 51821, local: "192.168.1.215"}
	if err := mapping.create(t.Context()); err != nil {
		t.Fatal(err)
	}
	if !router.added || mapping.Endpoint != "31.49.158.120:51821" {
		t.Fatal("leased direct endpoint was not created")
	}
	router.fault = nil
	router.internal = 51821
	router.local = "192.168.1.215"
	router.description = mappingDescription
	mapping.Close()
	if !router.deleted {
		t.Fatal("owned mapping was not cleaned")
	}
}

func TestMappingNeverOverwritesOrDeletesAnotherApplication(t *testing.T) {
	t.Parallel()
	router := &gatewayFixture{internal: 51821, local: "192.168.1.215", description: "Another application", external: "31.49.158.120"}
	mapping := &Mapping{gateway: router, port: 51821, local: "192.168.1.215"}
	if err := mapping.create(t.Context()); err == nil {
		t.Fatal("another application's mapping accepted")
	}
	mapping.Close()
	if router.added || router.deleted {
		t.Fatal("another application's mapping was changed")
	}
}

func TestMappingUnknownFaultAndCGNATFailClosed(t *testing.T) {
	t.Parallel()
	for _, router := range []*gatewayFixture{
		{fault: errors.New("router unavailable"), external: "31.49.158.120"},
		{internal: 51821, local: "192.168.1.215", description: mappingDescription, external: "100.64.1.1"},
	} {
		mapping := &Mapping{gateway: router, port: 51821, local: "192.168.1.215"}
		if err := mapping.create(t.Context()); err == nil || router.added {
			t.Fatal("unverified mapping/public endpoint accepted")
		}
	}
}
