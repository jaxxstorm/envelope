package attestation

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/jaxxstorm/envelope/internal/controller/config"
	"github.com/jaxxstorm/envelope/internal/controller/model"
	"github.com/jaxxstorm/envelope/internal/controller/strictjson"
)

func kernelValue(path, expected string) bool {
	file, err := os.Open(path)
	if err != nil {
		return false
	}
	defer file.Close()
	value, err := io.ReadAll(io.LimitReader(file, 129))
	return err == nil && len(value) <= 128 && strings.TrimSpace(string(value)) == expected
}

func readBounded(reader io.Reader, maximum int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(reader, maximum+1))
	if err != nil || int64(len(data)) > maximum {
		return nil, ErrRejected
	}
	return data, nil
}

type CollectorConfig struct {
	Topology               config.Topology    `json:"topology"`
	RouterID               string             `json:"router_id"`
	UnderlayInterface      string             `json:"underlay_interface"`
	PublicKey              string             `json:"ed25519_public_key"`
	MaximumTCPMSS          int                `json:"maximum_tcp_mss"`
	TransportRouteTableID  string             `json:"transport_route_table_id"`
	TransportAssociationID string             `json:"transport_association_id"`
	LocalDestinations      []LocalDestination `json:"local_destinations"`
}

type LocalDestination struct {
	Prefix           string `json:"prefix"`
	WorkloadSubnetID string `json:"workload_subnet_id"`
	EndpointID       string `json:"endpoint_id"`
}

func ParseCollectorConfig(reader io.Reader) (CollectorConfig, error) {
	var configuration CollectorConfig
	payload, err := readBounded(reader, 4*1024*1024)
	if err != nil || strictjson.Validate(payload, 4*1024*1024) != nil {
		return configuration, ErrRejected
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&configuration) != nil {
		return configuration, ErrRejected
	}
	if _, _, err := configuration.Authority(); err != nil {
		return configuration, err
	}
	return configuration, nil
}

func (c CollectorConfig) Authority() (model.DomainAuthority, model.OwnerAuthority, error) {
	if c.Topology.Validate() != nil || len(c.UnderlayInterface) == 0 || len(c.UnderlayInterface) > 15 || c.UnderlayInterface == "tailscale0" || c.UnderlayInterface == "envelope0" || c.UnderlayInterface == "lo" || c.UnderlayInterface == "all" || c.UnderlayInterface == "default" ||
		c.MaximumTCPMSS < 536 || c.MaximumTCPMSS > 1240 || !regexp.MustCompile(`^rtb-[0-9a-f]{8,17}$`).MatchString(c.TransportRouteTableID) || !regexp.MustCompile(`^rtbassoc-[0-9a-f]{8,17}$`).MatchString(c.TransportAssociationID) || !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(c.PublicKey) {
		return model.DomainAuthority{}, model.OwnerAuthority{}, ErrRejected
	}
	for _, character := range c.UnderlayInterface {
		if !(character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || character == '_' || character == '-' || character == '.') {
			return model.DomainAuthority{}, model.OwnerAuthority{}, ErrRejected
		}
	}
	for _, domain := range c.Topology.Domains {
		authority, err := c.Topology.DomainAuthority(domain.ID)
		if err != nil {
			return model.DomainAuthority{}, model.OwnerAuthority{}, ErrRejected
		}
		for _, owner := range authority.Owners {
			if owner.RouterID == c.RouterID {
				local := map[string]bool{}
				for _, site := range c.Topology.Sites {
					if site.ID == authority.SiteID {
						for _, prefix := range site.LocalPrefixes {
							local[prefix] = true
						}
					}
				}
				if len(c.LocalDestinations) != len(local) {
					return model.DomainAuthority{}, model.OwnerAuthority{}, ErrRejected
				}
				seenSubnets, seenEndpoints := map[string]bool{}, map[string]bool{}
				for _, destination := range c.LocalDestinations {
					if !local[destination.Prefix] || seenSubnets[destination.WorkloadSubnetID] || seenEndpoints[destination.EndpointID] || !regexp.MustCompile(`^subnet-[0-9a-f]{8,17}$`).MatchString(destination.WorkloadSubnetID) || !regexp.MustCompile(`^vpce-[0-9a-f]{8,17}$`).MatchString(destination.EndpointID) {
						return model.DomainAuthority{}, model.OwnerAuthority{}, ErrRejected
					}
					delete(local, destination.Prefix)
					seenSubnets[destination.WorkloadSubnetID] = true
					seenEndpoints[destination.EndpointID] = true
				}
				return authority, owner, nil
			}
		}
	}
	return model.DomainAuthority{}, model.OwnerAuthority{}, ErrRejected
}

func (c CollectorConfig) CanonicalJSON() ([]byte, error) {
	if _, _, err := c.Authority(); err != nil {
		return nil, err
	}
	topology, err := c.Topology.CanonicalJSON()
	if err != nil {
		return nil, err
	}
	clone := c
	if json.Unmarshal(topology, &clone.Topology) != nil {
		return nil, ErrRejected
	}
	clone.LocalDestinations = append([]LocalDestination(nil), c.LocalDestinations...)
	sort.Slice(clone.LocalDestinations, func(i, j int) bool { return clone.LocalDestinations[i].Prefix < clone.LocalDestinations[j].Prefix })
	return json.Marshal(clone)
}

func (c CollectorConfig) Hash() (string, error) {
	canonical, err := c.CanonicalJSON()
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(canonical)
	return hex.EncodeToString(digest[:]), nil
}
