package main

import (
	"strings"
	"testing"

	"f2n/internal/flowseal"
)

func TestParseALT11Fixture(t *testing.T) {
	p, err := flowseal.ParseBat(`testdata/flowseal/general (ALT11).bat`, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Profiles) != 9 {
		t.Fatalf("profiles = %d, want 9", len(p.Profiles))
	}
	if strings.Join(p.WfTCP, ",") != "80,443,2053,2083,2087,2096,8443" {
		t.Errorf("WfTCP = %v", p.WfTCP)
	}
	if strings.Join(p.WfUDP, ",") != "443,19294:19344,50000:50100" {
		t.Errorf("WfUDP = %v", p.WfUDP)
	}
	// profile 5 = tcp-main candidate: filter-tcp=80,443, three fakes, multisplit
	p5 := p.Profiles[4]
	if strings.Join(p5.FilterTCP, ",") != "80,443" || len(p5.Fakes) != 3 || !p5.AnyProtocol {
		// AnyProtocol must be false here
		if p5.AnyProtocol {
			t.Errorf("profile 5: AnyProtocol = true, want false")
		}
	}
	if len(p5.FilterTCP) != 2 || len(p5.Fakes) != 3 {
		t.Errorf("profile 5: tcp=%v fakes=%d", p5.FilterTCP, len(p5.Fakes))
	}
	// profiles 8 and 9 come from game filter vars -> GamePorts
	if !p.Profiles[7].GamePorts || !p.Profiles[8].GamePorts {
		t.Errorf("profiles 8/9 must be marked GamePorts")
	}
	// profile 1 must NOT be marked (its wf-* only carries the global var)
	if p.Profiles[0].GamePorts {
		t.Errorf("profile 1 must not be marked GamePorts")
	}
	if !p.GameUsed {
		t.Errorf("GameUsed = false, want true")
	}
}
