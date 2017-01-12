package nsstats

import (
	"fmt"
	"math/rand"
	"sync"

	"github.com/miekg/dns"
)

type statsType uint

const (
	InTld                statsType = 0
	InTldNoGlue          statsType = 1
	InTldNoGlueNoIp      statsType = 2
	InTldGlue            statsType = 3
	InTldGlueNoIp        statsType = 4
	InTldGlueIp          statsType = 5
	InTldGlueIpMissmatch statsType = 6
	ExTld                statsType = 7
	ExTldNoIp            statsType = 8
)

type Nsstat struct {
	access    sync.Mutex
	hostlist  Hostlist
	resolvers []string
	stats     map[statsType]uint
}

func Init(origin string, resolvers []string) *Nsstat {
	self := Nsstat{}
	self.access = sync.Mutex{}
	self.hostlist = Hostlist{}
	self.hostlist.Init(origin)
	self.resolvers = make([]string, 0)
	if len(resolvers) > 0 {
		for _, resolver := range resolvers {
			self.resolvers = append(self.resolvers, ip2resolver(resolver))
		}
	} else {
		self.resolvers = GetResolvers()
	}
	return &self
}

func (self *Nsstat) GetIPs(host *Host, wg *sync.WaitGroup) {
	defer wg.Done()
	self.access.Lock()
	resolver := self.resolvers[rand.Intn(len(self.resolvers))]
	self.access.Unlock()
	answer := resolv(host.GetName(), dns.TypeA, resolver)
	answer = append(answer, resolv(host.GetName(), dns.TypeAAAA, resolver)...)
	for _, answer := range answer {
		if answer.Header().Rrtype == dns.TypeA {
			host.AddIP(answer.(*dns.A).A)
		}
		if answer.Header().Rrtype == dns.TypeAAAA {
			host.AddIP(answer.(*dns.AAAA).AAAA)
		}
	}
}

func (self *Nsstat) Receive(rr dns.RR, wg *sync.WaitGroup) {
	defer wg.Done()

	switch rr.(type) {
	case *dns.NS:
		hostname := rr.(*dns.NS).Ns
		domain := rr.Header().Name
		host := self.hostlist.GetHost(hostname)
		if host == nil {
			host = self.hostlist.AddHost(hostname)
			wg.Add(1)
			go self.GetIPs(host, wg)
		}
		host.AddDomain(domain)
	case *dns.A:
		hostname := rr.Header().Name
		host := self.hostlist.GetHost(hostname)
		if host == nil {
			host = self.hostlist.AddHost(hostname)
			wg.Add(1)
			go self.GetIPs(host, wg)
		}
		glue := rr.(*dns.A).A
		host.AddGlue(glue)
	case *dns.AAAA:
		hostname := rr.Header().Name
		host := self.hostlist.GetHost(hostname)
		if host == nil {
			host = self.hostlist.AddHost(hostname)
			wg.Add(1)
			go self.GetIPs(host, wg)
		}
		glue := rr.(*dns.AAAA).AAAA
		host.AddGlue(glue)
	}
}

func (self *Nsstat) Done() {
	// init stats
	self.stats = make(map[statsType]uint, 9)

	// compute stats
	for _, host := range self.hostlist.list {
		if host.IsTldHost {
			self.stats[InTld]++
			if len(host.Glue) > 0 {
				// host has glue
				self.stats[InTldGlue]++
				if len(host.IPs) == 0 {
					// hosts has no ips resolved
					self.stats[InTldGlueNoIp]++
				} else {
					self.stats[InTldGlueIp]++

					// host has ips resolved
					GlueIpMissmatch := false

					// see if all glue records are found in resolved ip
					for _, glue := range host.Glue {
						found := false
						for _, ip := range host.IPs {
							if glue.Equal(ip) {
								found = true
							}
						}
						if !found {
							GlueIpMissmatch = true
						}
					}

					// see if all glue records are found in resolved ip
					for _, ip := range host.IPs {
						found := false
						for _, glue := range host.Glue {
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
						self.stats[InTldGlueIpMissmatch]++
					}
				}
			} else {
				// host has no glue
				self.stats[InTldNoGlue]++
				if len(host.IPs) == 0 {
					// host did not resolv, no ip
					self.stats[InTldNoGlueNoIp]++
				}
			}
		} else {
			// host out of zone
			self.stats[ExTld]++
			if len(host.IPs) == 0 {
				//host could not be resolved
				self.stats[ExTldNoIp]++
			}
		}
	}
}

func (self *Nsstat) Stats() {
	fmt.Printf("SE Hosts                                  %5d\n", self.stats[InTld])
	fmt.Printf("SE Hosts no glue        / no ip :         %5d / %5d  (%5.1f)\n", self.stats[InTldNoGlue], self.stats[InTldNoGlueNoIp], (100.0 * float64(self.stats[InTldNoGlueNoIp]) / float64(self.stats[InTldNoGlue])))
	fmt.Printf("SE Hosts    glue        / no ip :         %5d / %5d  (%5.1f)\n", self.stats[InTldGlue], self.stats[InTldGlueNoIp], (100.0 * float64(self.stats[InTldGlueNoIp]) / float64(self.stats[InTldGlue])))
	fmt.Printf("SE Hosts    glue and ip / not matching :  %5d / %5d  (%5.1f)\n", self.stats[InTldGlueIp], self.stats[InTldGlueIpMissmatch], (100.0 * float64(self.stats[InTldGlueIpMissmatch]) / float64(self.stats[InTldGlueIp])))
	fmt.Printf("EX Hosts                / no ip :         %5d / %5d  (%5.1f)\n", self.stats[ExTld], self.stats[ExTldNoIp], (100.0 * float64(self.stats[ExTldNoIp]) / float64(self.stats[ExTld])))
	fmt.Println("")
}

func (self *Nsstat) Influx(tld string, source string) string {
	line := fmt.Sprintf("Hosts,tld=%s,source=%s ", tld, source)
	line = line + fmt.Sprintf("InTld=%di", self.stats[InTld])
	line = line + fmt.Sprintf(",InTldNoGlue=%di", self.stats[InTldNoGlue])
	line = line + fmt.Sprintf(",InTldNoGlueNoIp=%di", self.stats[InTldNoGlueNoIp])
	line = line + fmt.Sprintf(",InTldGlue=%di", self.stats[InTldGlue])
	line = line + fmt.Sprintf(",InTldGlueNoIp=%di", self.stats[InTldGlueNoIp])
	line = line + fmt.Sprintf(",InTldGlueIp=%di", self.stats[InTldGlueIp])
	line = line + fmt.Sprintf(",InTldGlueIpMissmatch=%di", self.stats[InTldGlueIpMissmatch])
	line = line + fmt.Sprintf(",ExTld=%di", self.stats[ExTld])
	line = line + fmt.Sprintf(",ExTldNoIp=%di", self.stats[ExTldNoIp])
	line = line + "\n"
	return line
}
