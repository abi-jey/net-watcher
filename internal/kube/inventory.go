// Package kube provides optional, read-only Kubernetes inventory enrichment.
package kube

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

type Owner struct{ Kind, Name, UID string }
type Metadata struct {
	Name, Namespace, UID string
	Labels               map[string]string
	OwnerReferences      []Owner
}
type Port struct {
	Name, Protocol string
	Port, NodePort int
	TargetPort     json.RawMessage
}
type Object struct {
	Kind     string
	Metadata Metadata
	Spec     struct {
		NodeName    string
		HostNetwork bool
		ClusterIP   string
		ClusterIPs  []string
		ExternalIPs []string
		Addresses   []struct{ Type, IP string }
		Ports       []Port
	}
	Status struct {
		PodIP     string
		PodIPs    []struct{ IP string }
		Addresses []struct{ Type, Address string }
	}
	Endpoints []struct {
		Addresses []string
		TargetRef struct{ Kind, Name, Namespace, UID string }
	}
	Ports []struct {
		Name, Protocol string
		Port           int
	}
}
type List struct {
	Items    []Object
	Metadata struct{ Continue string }
}

// Source returns a complete inventory; partial refreshes must not replace the index.
type Source interface {
	List(context.Context) ([]Object, error)
}

// KubectlSource uses an explicitly selected user context without reading kubeconfig secrets.
type KubectlSource struct{ Context string }

func (s KubectlSource) List(ctx context.Context) ([]Object, error) {
	if s.Context == "" {
		return nil, fmt.Errorf("an explicit kube-context is required")
	}
	command := exec.CommandContext(ctx, "kubectl", "--context", s.Context, "--request-timeout=10s", "get", "pods,services,nodes,replicasets.apps,endpointslices.discovery.k8s.io", "--all-namespaces", "-o", "json")
	body, err := command.Output()
	if err != nil {
		return nil, fmt.Errorf("kubectl inventory request failed: %w", err)
	}
	var list List
	if err := json.Unmarshal(body, &list); err != nil {
		return nil, err
	}
	// Cilium host addresses are not always present in Node.status.addresses.
	// The CRD is optional so ordinary Kubernetes discovery still works without it.
	command = exec.CommandContext(ctx, "kubectl", "--context", s.Context, "--request-timeout=10s", "get", "ciliumnodes.cilium.io", "-o", "json")
	if body, err := command.Output(); err == nil {
		var cilium List
		if err := json.Unmarshal(body, &cilium); err != nil {
			return nil, err
		}
		for _, item := range cilium.Items {
			item.Kind = "CiliumNode"
			list.Items = append(list.Items, item)
		}
	}
	return list.Items, nil
}

type clusterSource struct {
	base      string
	client    *http.Client
	tokenFile string
}

// InClusterSource uses the projected service-account CA and renewable token.
func InClusterSource() (Source, error) {
	host, port := os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT")
	if host == "" || port == "" {
		return nil, fmt.Errorf("use --kube-context outside a Kubernetes pod")
	}
	const directory = "/var/run/secrets/kubernetes.io/serviceaccount/"
	certificate, err := os.ReadFile(directory + "ca.crt")
	if err != nil {
		return nil, fmt.Errorf("read service-account CA: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(certificate) {
		return nil, fmt.Errorf("invalid service-account CA")
	}
	client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return &clusterSource{base: "https://" + net.JoinHostPort(host, port), client: client, tokenFile: directory + "token"}, nil
}

func (s *clusterSource) List(ctx context.Context) ([]Object, error) {
	resources := []struct {
		path, kind string
		optional   bool
	}{
		{path: "/api/v1/pods", kind: "Pod"},
		{path: "/api/v1/services", kind: "Service"},
		{path: "/api/v1/nodes", kind: "Node"},
		{path: "/apis/apps/v1/replicasets", kind: "ReplicaSet"},
		{path: "/apis/discovery.k8s.io/v1/endpointslices", kind: "EndpointSlice"},
		{path: "/apis/cilium.io/v2/ciliumnodes", kind: "CiliumNode", optional: true},
	}
	var result []Object
	for _, resource := range resources {
		next := ""
		for {
			token, err := os.ReadFile(s.tokenFile)
			if err != nil {
				return nil, fmt.Errorf("read service-account token: %w", err)
			}
			query := url.Values{"limit": {"500"}}
			if next != "" {
				query.Set("continue", next)
			}
			request, err := http.NewRequestWithContext(ctx, http.MethodGet, s.base+resource.path+"?"+query.Encode(), nil)
			if err != nil {
				return nil, err
			}
			request.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(token)))
			response, err := s.client.Do(request)
			if err != nil {
				return nil, fmt.Errorf("Kubernetes %s request failed", resource.kind)
			}
			if response.StatusCode != http.StatusOK {
				response.Body.Close()
				if resource.optional && (response.StatusCode == http.StatusForbidden || response.StatusCode == http.StatusNotFound) {
					break
				}
				return nil, fmt.Errorf("Kubernetes %s: HTTP %d", resource.kind, response.StatusCode)
			}
			var list List
			err = json.NewDecoder(response.Body).Decode(&list)
			response.Body.Close()
			if err != nil {
				return nil, fmt.Errorf("decode Kubernetes %s: %w", resource.kind, err)
			}
			for _, item := range list.Items {
				item.Kind = resource.kind
				result = append(result, item)
			}
			if len(result) > 100000 {
				return nil, fmt.Errorf("inventory exceeds 100000 resources")
			}
			next = list.Metadata.Continue
			if next == "" {
				break
			}
		}
	}
	return result, nil
}

type Service struct {
	Namespace, Name, UID string
	Port                 int
	Protocol             string
}

// Endpoint describes inventory observed at capture time, not a proven NAT path.
type Endpoint struct {
	Kind, Namespace, Name, UID, Node string
	Owner                            Owner
	Services                         []Service `json:",omitempty"`
	ObservedAt                       time.Time
}
type Status struct {
	Enabled   bool
	LastSync  time.Time
	Error     string
	Resources int
}
type serviceKey struct {
	IP, Protocol string
	Port         int
}
type Index struct {
	mu        sync.RWMutex
	source    Source
	endpoints map[string]Endpoint
	services  map[serviceKey][]Service
	status    Status
}

func New(source Source) *Index  { return &Index{source: source, status: Status{Enabled: source != nil}} }
func (i *Index) Status() Status { i.mu.RLock(); defer i.mu.RUnlock(); return i.status }

func (i *Index) Refresh(ctx context.Context) error {
	objects, err := i.source.List(ctx)
	if err != nil {
		i.mu.Lock()
		i.status.Error = err.Error()
		i.mu.Unlock()
		return err
	}
	i.Replace(objects, time.Now())
	return nil
}

// Run refreshes inventory periodically; old data becomes unusable after 90 seconds.
func (i *Index) Run(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			refreshCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
			_ = i.Refresh(refreshCtx)
			cancel()
		}
	}
}

// Replace publishes one consistent inventory snapshot. Host-network pods do not
// take ownership of their shared node IP; EndpointSlices provide service candidates.
func (i *Index) Replace(objects []Object, at time.Time) {
	endpoints := make(map[string]Endpoint)
	services := make(map[serviceKey][]Service)
	owners := make(map[string]Owner)
	serviceIDs := make(map[string]string)
	for _, object := range objects {
		if object.Kind == "ReplicaSet" && len(object.Metadata.OwnerReferences) > 0 {
			owners[object.Metadata.UID] = object.Metadata.OwnerReferences[0]
		}
		if object.Kind == "Service" {
			serviceIDs[object.Metadata.Namespace+"/"+object.Metadata.Name] = object.Metadata.UID
		}
	}
	for _, object := range objects {
		m := object.Metadata
		endpoint := Endpoint{Kind: strings.ToLower(object.Kind), Namespace: m.Namespace, Name: m.Name, UID: m.UID, Node: object.Spec.NodeName, ObservedAt: at}
		if len(m.OwnerReferences) > 0 {
			endpoint.Owner = m.OwnerReferences[0]
			if owner, ok := owners[endpoint.Owner.UID]; ok {
				endpoint.Owner = owner
			}
		}
		switch object.Kind {
		case "Pod":
			if object.Spec.HostNetwork {
				continue
			}
			if object.Status.PodIP != "" {
				endpoints[object.Status.PodIP] = endpoint
			}
			for _, address := range object.Status.PodIPs {
				endpoints[address.IP] = endpoint
			}
		case "Service":
			ips := append(append([]string{}, object.Spec.ClusterIPs...), object.Spec.ExternalIPs...)
			ips = append(ips, object.Spec.ClusterIP)
			for _, ip := range ips {
				if net.ParseIP(ip) != nil {
					endpoints[ip] = endpoint
				}
			}
		case "EndpointSlice":
			name := m.Labels["kubernetes.io/service-name"]
			if name == "" {
				continue
			}
			for _, ep := range object.Endpoints {
				for _, ip := range ep.Addresses {
					for _, port := range object.Ports {
						key := serviceKey{ip, strings.ToUpper(port.Protocol), port.Port}
						if key.Protocol == "" {
							key.Protocol = "TCP"
						}
						services[key] = append(services[key], Service{Namespace: m.Namespace, Name: name, UID: serviceIDs[m.Namespace+"/"+name], Port: port.Port, Protocol: key.Protocol})
					}
				}
			}
		}
	}
	// Node addresses take precedence over host-network/service aliases sharing them.
	nodesByName := make(map[string]Endpoint)
	for _, object := range objects {
		if object.Kind == "Node" {
			endpoint := Endpoint{Kind: "node", Name: object.Metadata.Name, UID: object.Metadata.UID, Node: object.Metadata.Name, ObservedAt: at}
			nodesByName[object.Metadata.Name] = endpoint
			for _, address := range object.Status.Addresses {
				if net.ParseIP(address.Address) != nil {
					endpoints[address.Address] = endpoint
				}
			}
		}
	}
	for _, object := range objects {
		if object.Kind != "CiliumNode" {
			continue
		}
		endpoint, known := nodesByName[object.Metadata.Name]
		if !known {
			continue
		}
		for _, address := range object.Spec.Addresses {
			if address.Type == "CiliumInternalIP" && net.ParseIP(address.IP) != nil {
				endpoints[address.IP] = endpoint
			}
		}
	}
	for _, object := range objects {
		if object.Kind == "Service" {
			for _, port := range object.Spec.Ports {
				if port.NodePort == 0 {
					continue
				}
				protocol := strings.ToUpper(port.Protocol)
				if protocol == "" {
					protocol = "TCP"
				}
				for ip, endpoint := range endpoints {
					if endpoint.Kind == "node" {
						key := serviceKey{ip, protocol, port.NodePort}
						services[key] = append(services[key], Service{Namespace: object.Metadata.Namespace, Name: object.Metadata.Name, UID: object.Metadata.UID, Port: port.NodePort, Protocol: protocol})
					}
				}
			}
		}
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	i.endpoints, i.services = endpoints, services
	i.status = Status{Enabled: true, LastSync: at, Resources: len(objects)}
}

func (i *Index) Lookup(ip string, port uint16, protocol string) string {
	i.mu.RLock()
	defer i.mu.RUnlock()
	if i.status.LastSync.IsZero() || time.Since(i.status.LastSync) > 90*time.Second {
		return ""
	}
	endpoint, exists := i.endpoints[ip]
	candidates := i.services[serviceKey{ip, strings.ToUpper(protocol), int(port)}]
	if !exists && len(candidates) == 0 {
		return ""
	}
	if !exists {
		endpoint = Endpoint{Kind: "endpoint", ObservedAt: i.status.LastSync}
	}
	endpoint.Services = candidates
	encoded, _ := json.Marshal(endpoint)
	return string(encoded)
}
