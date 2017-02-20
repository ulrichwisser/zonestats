package unregns

import (
	"fmt"
	"strings"
	"sync"

	"github.com/miekg/dns"
)

type Domain struct {
	name string
	ns   []string
}
type UnRegNS struct {
	access     sync.Mutex
	domainlist map[string]Domain
	hostlist   map[string]uint
	results    map[string]Domain
}

func Init() *UnRegNS {
	self := UnRegNS{}
	self.access = sync.Mutex{}
	self.domainlist = make(map[string]Domain, 0)
	self.hostlist = make(map[string]uint, 0)
	return &self
}

func (self *UnRegNS) Receive(rr dns.RR, wg *sync.WaitGroup) {
	defer wg.Done()

	switch rr.(type) {
	case *dns.NS:
		hostname := rr.(*dns.NS).Ns
		domain := rr.Header().Name
		self.access.Lock()
		defer self.access.Unlock()
		if _, ok := self.domainlist[domain]; !ok {
			self.domainlist[domain] = Domain{name: domain, ns: []string{hostname}}
		} else {
			dom := self.domainlist[domain]
			dom.ns = append(dom.ns, hostname)
		}
		if strings.HasSuffix(hostname, ".se.") {
			self.hostlist[hostname] = 1
		}
	}
}

func (self *UnRegNS) hostNotFound(domain string, host string) {
	if _, ok := self.results[domain]; !ok {
		self.results[domain] = Domain{name: domain, ns: []string{host}}
	} else {
		dom := self.results[domain]
		dom.ns = append(dom.ns, host)
	}
}

func (self *UnRegNS) Done() {
	self.results = make(map[string]Domain, 0)
	fmt.Printf("CMP  DOMAINS %d   HOSTS %d\n", len(self.domainlist), len(self.hostlist))
	for host := range self.hostlist {
		found := false
		for domain := range self.domainlist {
			fmt.Printf("CMP %s %s\n", host, domain)
			if host == domain {
				found = true
				break
			}
			if strings.HasSuffix(host, "."+domain) {
				found = true
				break
			}
		}
		if !found {
			fmt.Printf("UNREGNS %s\n", host)
		}
	}
}

func (self *UnRegNS) Stats() {
	for domain := range self.results {
		for _, host := range self.results[domain].ns {
			fmt.Printf("UNREGNS  %-25s %-25s\n", domain, host)
		}
	}
	fmt.Println("")
}

func (self *UnRegNS) Influx(tld string, source string) string {
	line := fmt.Sprintf("Hosts,tld=%s,source=%s ", tld, source)
	line = line + "\n"
	return line
}
