package countdom

import (
	"fmt"
	"sync"

	"github.com/miekg/dns"
)

type CountDom struct {
	count  map[string]uint
	access sync.Mutex
}

func Init() *CountDom {
	self := CountDom{}
	self.count = make(map[string]uint)
	self.access = sync.Mutex{}
	return &self
}

func (self *CountDom) Receive(rr dns.RR, wg *sync.WaitGroup) {
	defer wg.Done()
	dom := rr.Header().Name
	self.access.Lock()
	defer self.access.Unlock()
	if _, ok := self.count[dom]; !ok {
		self.count[dom] = 0
	}
	self.count[dom]++
}

func (self *CountDom) Done() {
}

func (self *CountDom) Stats() {
	fmt.Printf("CountDom\t%7d\n", len(self.count))
}

func (self *CountDom) Influx(tld string, source string) string {
	return fmt.Sprintf("CountDom,tld=%s,source=%s value=%di\n", tld, source, len(self.count))
}
