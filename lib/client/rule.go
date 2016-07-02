package client

import (
	"github.com/projectcalico/libcalico/lib/api"
	"github.com/projectcalico/libcalico/lib/backend"
)

func ruleActionAPIToBackend(action string) string {
	if action == "nextTier" {
		return "next-tier"
	}
	return action
}

func ruleActionBackendToAPI(action string) string {
	if action == "next-tier" {
		return "nextTier"
	}
	return action
}

// Convert an API Rule structure to a Backend Rule structure
func ruleAPIToBackend(ar api.Rule) backend.Rule {
	return backend.Rule{
		Action:   ruleActionAPIToBackend(ar.Action),
		ICMPCode: ar.ICMPCode,
		ICMPType: ar.ICMPType,

		SrcTag:      ar.Source.Tag,
		SrcNet:      ar.Source.Net,
		SrcSelector: ar.Source.Selector,
		SrcPorts:    ar.Source.Ports,
		DstTag:      ar.Destination.Tag,
		DstNet:      ar.Destination.Net,
		DstSelector: ar.Destination.Selector,
		DstPorts:    ar.Destination.Ports,

		NotSrcTag:      ar.Source.NotTag,
		NotSrcNet:      ar.Source.NotNet,
		NotSrcSelector: ar.Source.NotSelector,
		NotSrcPorts:    ar.Source.NotPorts,
		NotDstTag:      ar.Destination.NotTag,
		NotDstNet:      ar.Destination.NotNet,
		NotDstSelector: ar.Destination.NotSelector,
		NotDstPorts:    ar.Destination.NotPorts,
	}
}

// Convert a Backend Rule structure to an API Rule structure
func ruleBackendToAPI(br backend.Rule) api.Rule {
	return api.Rule{
		Action:   ruleActionBackendToAPI(br.Action),
		ICMPCode: br.ICMPCode,
		ICMPType: br.ICMPType,

		Source: api.EntityRule{
			Tag:         br.SrcTag,
			Net:         br.SrcNet,
			Selector:    br.SrcSelector,
			Ports:       br.SrcPorts,
			NotTag:      br.NotSrcTag,
			NotNet:      br.NotSrcNet,
			NotSelector: br.NotSrcSelector,
			NotPorts:    br.NotSrcPorts,
		},

		Destination: api.EntityRule{
			Tag:         br.DstTag,
			Net:         br.DstNet,
			Selector:    br.DstSelector,
			Ports:       br.DstPorts,
			NotTag:      br.NotDstTag,
			NotNet:      br.NotDstNet,
			NotSelector: br.NotDstSelector,
			NotPorts:    br.NotDstPorts,
		},
	}
}

// Convert an API Rule structure slice to a Backend Rule structure slice
func rulesAPIToBackend(ars []api.Rule) []backend.Rule {
	if ars == nil {
		return nil
	}

	brs := make([]backend.Rule, len(ars))
	for idx, ar := range ars {
		brs[idx] = ruleAPIToBackend(ar)
	}
	return brs
}

// Convert a Backend Rule structure slice to an API Rule structure slice
func rulesBackendToAPI(brs []backend.Rule) []api.Rule {
	if brs == nil {
		return nil
	}

	ars := make([]api.Rule, len(brs))
	for idx, br := range brs {
		ars[idx] = ruleBackendToAPI(br)
	}
	return ars
}
