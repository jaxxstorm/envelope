package attestation

import (
	"github.com/jaxxstorm/envelope/internal/controller/config"
	"net/netip"
	"reflect"
	"sort"
	"time"

	"tailscale.com/ipn/ipnstate"
)

func configuredPeerForPrefix(topology config.Topology, prefix, node string) bool {
	for _, site := range topology.Sites {
		for _, local := range site.LocalPrefixes {
			if local != prefix {
				continue
			}
			for _, router := range topology.Routers {
				if router.SiteID == site.ID && router.StableNodeID == node {
					return true
				}
			}
		}
	}
	return false
}

// AllowedIPs is populated for Self and peers by the pinned 1.80.3 LocalAPI
// peerStatusFromNode. Host addresses are not approved subnet advertisements.
func subnetRoutes(peer *ipnstate.PeerStatus) ([]string, error) {
	if peer == nil {
		return nil, ErrRejected
	}
	result := []string{}
	seen := map[netip.Prefix]bool{}
	if peer.AllowedIPs == nil {
		return result, nil
	}
	for _, prefix := range peer.AllowedIPs.AsSlice() {
		if !prefix.IsValid() || prefix != prefix.Masked() || seen[prefix] {
			return nil, ErrRejected
		}
		seen[prefix] = true
		host := false
		if prefix.IsSingleIP() {
			for _, ip := range peer.TailscaleIPs {
				if prefix.Addr() == ip {
					host = true
				}
			}
		}
		if !host {
			result = append(result, prefix.String())
		}
	}
	sort.Strings(result)
	return result, nil
}

func exactTailnetRoutes(status *ipnstate.Status, local, remote []string) bool {
	enabled, err := subnetRoutes(status.Self)
	if err != nil || !reflect.DeepEqual(enabled, local) {
		return false
	}
	wanted, own := map[string]bool{}, map[string]bool{}
	for _, prefix := range remote {
		wanted[prefix] = false
	}
	for _, prefix := range local {
		own[prefix] = true
	}
	for _, peer := range status.Peer {
		routes, err := subnetRoutes(peer)
		if err != nil {
			return false
		}
		for _, route := range routes {
			if own[route] {
				continue
			}
			if _, ok := wanted[route]; !ok {
				return false
			}
			wanted[route] = true
		}
	}
	for _, found := range wanted {
		if !found {
			return false
		}
	}
	return true
}

func servingOwners(status *ipnstate.Status, remote []string) (map[string]string, error) {
	result := map[string]string{}
	for _, prefix := range remote {
		for _, peer := range status.Peer {
			if peer == nil || peer.PrimaryRoutes == nil {
				continue
			}
			for _, route := range peer.PrimaryRoutes.AsSlice() {
				if route.String() != prefix {
					continue
				}
				if result[prefix] != "" || peer.ID == "" || !peer.Online || peer.Expired || (peer.KeyExpiry != nil && !peer.KeyExpiry.After(time.Now())) {
					return nil, ErrRejected
				}
				result[prefix] = string(peer.ID)
			}
		}
		if result[prefix] == "" {
			return nil, ErrRejected
		}
	}
	return result, nil
}
