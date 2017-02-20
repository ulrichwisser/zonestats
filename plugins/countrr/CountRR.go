package countrr

import (
	"errors"
	"fmt"
	"sync"

	"github.com/miekg/dns"
)

type CountRR struct {
	count  map[string]uint
	access sync.Mutex
}

func Init() *CountRR {
	self := CountRR{}
	self.count = make(map[string]uint)
	self.access = sync.Mutex{}
	return &self
}

func (self *CountRR) Receive(rr dns.RR, wg *sync.WaitGroup) {
	defer wg.Done()
	rrtype := dns.Type(rr.Header().Rrtype).String()
	if len(rrtype) == 0 {
		panic(errors.New("Unknown RRTYPE: " + rr.String()))
	}
	self.access.Lock()
	defer self.access.Unlock()
	if _, ok := self.count[rrtype]; !ok {
		self.count[rrtype] = 0
	}
	self.count[rrtype]++
}

func (self *CountRR) Done() {
}

func (self *CountRR) Influx(tld string, source string) string {
	line := fmt.Sprintf("CountRR,tld=%s,source=%s ", tld, source)
	seperator := ""
	for rrtype, count := range self.count {
		line = line + seperator + fmt.Sprintf("%s=%di", rrtype, count)
		seperator = ","
	}
	line = line + "\n"
	return line
}
