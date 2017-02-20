package dnssec

import (
	"fmt"
	"sync"

	"github.com/miekg/dns"
)

type DNSSEC struct {
	measurement    map[string]map[uint8]map[uint8]uint
	CountDS        map[uint8]map[uint8]uint
	CountDomDS     map[uint8]uint
	CountDomDnskey map[uint8]uint
	access         sync.Mutex
}

func Init() *DNSSEC {
	self := DNSSEC{}
	self.measurement = make(map[string]map[uint8]map[uint8]uint)
	self.access = sync.Mutex{}
	return &self
}

func (self *DNSSEC) Receive(rr dns.RR, wg *sync.WaitGroup) {
	defer wg.Done()
	self.access.Lock()
	switch rr.(type) {
	case *dns.DS:
		ds := rr.(*dns.DS)
		dom := rr.Header().Name

		// count algorithm
		if _, ok := self.measurement[dom]; !ok {
			self.measurement[dom] = make(map[uint8]map[uint8]uint)
		}
		if _, ok := self.measurement[dom][ds.Algorithm]; !ok {
			self.measurement[dom][ds.Algorithm] = make(map[uint8]uint, 0)
		}
		if _, ok := self.measurement[dom][ds.Algorithm][ds.DigestType]; !ok {
			self.measurement[dom][ds.Algorithm][ds.DigestType] = 1
		} else {
			self.measurement[dom][ds.Algorithm][ds.DigestType]++
		}
	}
	self.access.Unlock()
}

func AlgorithmName(alg uint8) string {
	var str string
	var ok bool
	if str, ok = dns.AlgorithmToString[alg]; !ok {
		str = fmt.Sprintf("%d", alg)
	}
	return str
}

func DigestTypeName(dt uint8) string {
	var str string
	var ok bool
	if str, ok = dns.HashToString[dt]; !ok {
		str = fmt.Sprintf("%d", dt)
	}
	return str
}

func (self *DNSSEC) Done() {
	// init stats counters
	self.CountDS = make(map[uint8]map[uint8]uint)
	self.CountDomDS = make(map[uint8]uint)
	self.CountDomDnskey = make(map[uint8]uint)

	// compute stats
	for dom := range self.measurement {
		for alg := range self.measurement[dom] {
			for digest := range self.measurement[dom][alg] {
				// CountDS
				if _, ok := self.CountDS[alg]; !ok {
					self.CountDS[alg] = make(map[uint8]uint)
				}
				if _, ok := self.CountDS[alg][digest]; !ok {
					self.CountDS[alg][digest] = 1
				} else {
					self.CountDS[alg][digest]++
				}

				// CountDomDS
				if _, ok := self.CountDomDS[digest]; !ok {
					self.CountDomDS[digest] = 1
				} else {
					self.CountDomDS[digest]++
				}

				// CountDomDnskey
				if _, ok := self.CountDomDS[digest]; !ok {
					self.CountDomDS[digest] = 1
				} else {
					self.CountDomDS[digest]++
				}

			}
		}
	}
}

func (self *DNSSEC) Stats() {
	for alg := range self.CountDS {
		for digest := range self.CountDS[alg] {
			fmt.Printf("Dnssec\t%-25s\t%-10s\t%d\n", AlgorithmName(alg), DigestTypeName(digest), self.CountDS[alg][digest])
		}
	}
	fmt.Printf("CountSigned\t%d\n", len(self.measurement))
}

func (self *DNSSEC) Influx(tld string, source string) string {
	line := ""
	for alg := range self.CountDS {
		for digest := range self.CountDS[alg] {
			line = line + fmt.Sprintf("CountDS,tld=%s,source=%s,algorithm=%s,digesttype=%s count=%di\n", tld, source, AlgorithmName(alg), DigestTypeName(digest), self.CountDS[alg][digest])
		}
	}
	line = line + fmt.Sprintf("CountDomSigned,tld=%s,source=%s value=%di\n", tld, source, len(self.measurement))
	return line
}
