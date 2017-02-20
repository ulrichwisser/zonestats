package hostlist

import (
	"net"
	"strings"
	"sync"

	"github.com/miekg/dns"
)

type Host struct {
	Access    sync.Mutex
	Name      string
	Domains   []string
	IPs       []net.IP
	Glue      []net.IP
	IsTldHost bool
}

type Hostlist struct {
	Access sync.Mutex
	List   map[string]*Host
	Origin string
}

func (self *Hostlist) Init(origin string) {
	self.List = make(map[string]*Host, 0)
	self.Origin = "." + dns.Fqdn(origin)
}

func (self *Hostlist) GetHost(hostname string) *Host {
	self.Access.Lock()
	defer self.Access.Unlock()
	host, ok := self.List[hostname]
	if !ok {
		return nil
	}
	return host
}

func (self *Hostlist) GetAllHostnames() []string {
	hosts := make([]string, 0)
	self.Access.Lock()
	defer self.Access.Unlock()
	for host := range self.List {
		hosts = append(hosts, host)
	}
	return hosts
}

func (self *Hostlist) AddHost(hostname string) *Host {
	self.Access.Lock()
	defer self.Access.Unlock()
	if _, ok := self.List[hostname]; !ok {
		self.List[hostname] = &Host{Name: hostname, Domains: nil, IPs: nil, Glue: nil, IsTldHost: strings.HasSuffix(hostname, self.Origin)}
	}
	return self.List[hostname]
}

func (self *Host) GetName() string {
	self.Access.Lock()
	defer self.Access.Unlock()
	return self.Name
}

func (self *Host) AddDomain(domain string) {
	self.Access.Lock()
	defer self.Access.Unlock()
	self.Domains = append(self.Domains, domain)
}

func (self *Host) AddIP(ip net.IP) {
	self.Access.Lock()
	defer self.Access.Unlock()
	self.IPs = append(self.IPs, ip)
}

func (self *Host) AddGlue(glue net.IP) {
	self.Access.Lock()
	defer self.Access.Unlock()
	self.Glue = append(self.Glue, glue)
}
