package nsstats

import (
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/miekg/dns"
)

type Host struct {
	access    sync.Mutex
	Name      string
	Domains   []string
	IPs       []net.IP
	Glue      []net.IP
	IsTldHost bool
}

type Hostlist struct {
	access sync.Mutex
	list   map[string]*Host
	origin string
}

func (self *Hostlist) Init(origin string) {
	self.list = make(map[string]*Host, 0)
	self.origin = "." + dns.Fqdn(origin)
}

func (self *Hostlist) GetHost(hostname string) *Host {
	self.access.Lock()
	defer self.access.Unlock()
	host, ok := self.list[hostname]
	if !ok {
		return nil
	}
	return host
}

func (self *Hostlist) GetAllHostnames() []string {
	hosts := make([]string, 0)
	self.access.Lock()
	defer self.access.Unlock()
	for host := range self.list {
		hosts = append(hosts, host)
	}
	return hosts
}

func (self *Hostlist) AddHost(hostname string) *Host {
	self.access.Lock()
	defer self.access.Unlock()
	if _, ok := self.list[hostname]; !ok {
		self.list[hostname] = &Host{Name: hostname, Domains: nil, IPs: nil, Glue: nil, IsTldHost: strings.HasSuffix(hostname, self.origin)}
	}
	return self.list[hostname]
}

func (self *Host) GetName() string {
	self.access.Lock()
	defer self.access.Unlock()
	return self.Name
}

func (self *Host) AddDomain(domain string) {
	self.access.Lock()
	defer self.access.Unlock()
	self.Domains = append(self.Domains, domain)
}

func (self *Host) AddIP(ip net.IP) {
	self.access.Lock()
	defer self.access.Unlock()
	self.IPs = append(self.IPs, ip)
}

func (self *Host) AddGlue(glue net.IP) {
	self.access.Lock()
	defer self.access.Unlock()
	self.Glue = append(self.Glue, glue)
}

func (self *Hostlist) Stats() {
	fmt.Println("--------------------------------")
	fmt.Println("Stats")
	fmt.Println("--------------------------------")

	var SEhosts = 0
	var SEhostsNoGlue = 0
	var SEhostsGlue = 0
	var SEhostsNoGlueNoIP = 0
	var SEhostsGlueNoIP = 0
	var SEhostsGlueNotInIP = 0

	var EXhosts = 0
	var EXhostsNoIP = 0

	for host := range self.list {
		if self.list[host].IsTldHost {
			SEhosts++
			if len(self.list[host].Glue) > 0 {
				// host has glue
				SEhostsGlue++
				if len(self.list[host].IPs) == 0 {
					// hosts has no ips resolved
					SEhostsGlueNoIP++
				} else {
					// host has ips resolved
					GlueIpMissmatch := false

					// see if all glue records are found in resolved ip
					for _, glue := range self.list[host].Glue {
						found := false
						for _, ip := range self.list[host].IPs {
							if glue.Equal(ip) {
								found = true
							}
						}
						if !found {
							GlueIpMissmatch = true
						}
					}

					// see if all glue records are found in resolved ip
					for _, ip := range self.list[host].IPs {
						found := false
						for _, glue := range self.list[host].Glue {
							if ip.Equal(glue) {
								found = true
							}
						}
						if !found {
							GlueIpMissmatch = true
						}
					}

					// count missmatch
					if GlueIpMissmatch {
						SEhostsGlueNotInIP++
					}
				}
			} else {
				// host has no glue
				SEhostsNoGlue++
				if len(self.list[host].IPs) == 0 {
					// host did not resolv, no ip
					SEhostsNoGlueNoIP++
				}
			}
		} else {
			// host out of zone
			EXhosts++
			if len(self.list[host].IPs) == 0 {
				//host could not be resolved
				EXhostsNoIP++
			}
		}
	}
	fmt.Printf("SE Hosts no glue        / no ip :         %5d / %5d  (%5.1f)\n", SEhostsNoGlue, SEhostsNoGlueNoIP, (100.0 * float64(SEhostsNoGlueNoIP) / float64(SEhostsNoGlue)))
	fmt.Printf("SE Hosts    glue        / no ip :         %5d / %5d  (%5.1f)\n", SEhostsGlue, SEhostsGlueNoIP, (100.0 * float64(SEhostsGlueNoIP) / float64(SEhostsGlue)))
	fmt.Printf("SE Hosts    glue and ip / not matching :  %5d / %5d  (%5.1f)\n", (SEhostsGlue - SEhostsGlueNoIP), SEhostsGlueNotInIP, (100.0 * float64(SEhostsGlueNotInIP) / float64(SEhostsGlue-SEhostsGlueNoIP)))
	fmt.Printf("EX Hosts                / no ip :         %5d / %5d  (%5.1f)\n", EXhosts, EXhostsNoIP, (100.0 * float64(EXhostsNoIP) / float64(EXhosts)))
	fmt.Println("")
}
