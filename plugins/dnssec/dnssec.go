package dnssec

import (
	"fmt"
	"sync"

	"github.com/miekg/dns"
)

type DNSSEC struct {
	measurement map[uint8]map[uint8]uint
	access      sync.Mutex
}

func Init() *DNSSEC {
	self := DNSSEC{}
	self.measurement = make(map[uint8]map[uint8]uint)
	self.access = sync.Mutex{}
	return &self
}

func (self *DNSSEC) Receive(rr dns.RR, wg *sync.WaitGroup) {
	defer wg.Done()
	self.access.Lock()
	switch rr.(type) {
	case *dns.DS:
		ds := rr.(*dns.DS)

		// count algorithm
		if _, ok := self.measurement[ds.Algorithm]; !ok {
			self.measurement[ds.Algorithm] = make(map[uint8]uint, 0)
		}
		if _, ok := self.measurement[ds.Algorithm][ds.DigestType]; !ok {
			self.measurement[ds.Algorithm][ds.DigestType] = 1
		} else {
			self.measurement[ds.Algorithm][ds.DigestType]++
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
}

func (self *DNSSEC) Stats() {
	for alg := range self.measurement {
		for digest := range self.measurement[alg] {
			fmt.Printf("Dnssec\t%-25s\t%-10s\t%d\n", AlgorithmName(alg), DigestTypeName(digest), self.measurement[alg][digest])
		}
	}
}

func (self *DNSSEC) Influx(tld string, source string) string {
	line := ""
	for alg := range self.measurement {
		for digest := range self.measurement[alg] {
			line = line + fmt.Sprintf("CountDS,tld=%s,source=%s,algorithm=%s,digesttype=%s count=%di\n", tld, source, AlgorithmName(alg), DigestTypeName(digest), self.measurement[alg][digest])
		}
	}
	return line
}
