package nsstats

import (
	"fmt"
	"sync"

	"github.com/miekg/dns"
	"github.com/ulrichwisser/zonestats/dnsresolver"
	"github.com/ulrichwisser/zonestats/hostlist"
	"github.com/ulrichwisser/zonestats/iplist"
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

	IpEdns0        statsType = 21
	IpNoEdns0      statsType = 22
	IpNsid         statsType = 23
	IpNoNsid       statsType = 24
	IpDnscookies   statsType = 25
	IpNoDnscookies statsType = 26
)

const STATS_SIZE = 30

type Nsstat struct {
	access   sync.Mutex
	hostlist hostlist.Hostlist
	iplist   iplist.IPlist
	resolver *dnsresolver.Resolver
	stats    map[statsType]uint
}

func Init(origin string, resolver *dnsresolver.Resolver) *Nsstat {
	self := Nsstat{}
	self.access = sync.Mutex{}
	self.hostlist = hostlist.Hostlist{}
	self.hostlist.Init(origin)
	self.iplist = iplist.IPlist{}
	self.iplist.Init()
	self.resolver = resolver
	return &self
}

func (self *Nsstat) GetIPs(host *hostlist.Host, wg *sync.WaitGroup) {
	defer wg.Done()
	self.access.Lock()
	self.access.Unlock()
	answer := self.resolver.Resolv(host.GetName(), dns.TypeA)
	answer = append(answer, self.resolver.Resolv(host.GetName(), dns.TypeAAAA)...)
	for _, answer := range answer {
		if answer.Header().Rrtype == dns.TypeA {
			host.AddIP(answer.(*dns.A).A)
			self.iplist.AddIP(answer.(*dns.A).A, wg)
		}
		if answer.Header().Rrtype == dns.TypeAAAA {
			host.AddIP(answer.(*dns.AAAA).AAAA)
			self.iplist.AddIP(answer.(*dns.AAAA).AAAA, wg)
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
		self.iplist.AddIP(glue, wg)
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
		self.iplist.AddIP(glue, wg)
	}
}

func (self *Nsstat) HostStats() {
	for _, host := range self.hostlist.List {
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

func (self *Nsstat) IpStats() {
	for i, cap := range self.iplist.Results {
		fmt.Printf("%3d: IP %-15s  EDNS0 %t COOKIES %t NSID %-15s BIND %-15s\n", i, cap.Ip.String(), cap.EDNS0, cap.DNSCookies, cap.NSID, cap.BINDVERSION)
	}
}

func (self *Nsstat) Done() {
	// init stats
	self.stats = make(map[statsType]uint, STATS_SIZE)

	// compute stats
	self.HostStats()
	self.IpStats()
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
