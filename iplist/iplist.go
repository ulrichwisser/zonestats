package iplist

import (
	"fmt"
	"math/rand"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/ulrichwisser/zonestats/dnsresolver"
)

const (
	EDNS0SIZE               = 4096
	TIMEOUT   time.Duration = time.Duration(5) * time.Second
	RATELIMIT uint          = 100
)

var ratelimiter = make(chan string, RATELIMIT)

type IpCap struct {
	Ip          net.IP
	EDNS0       bool
	DNSCookies  bool
	NSID        string
	BINDVERSION string
}

type IPlist struct {
	Access  sync.Mutex
	List    []*net.IP
	Results []IpCap
}

func (self *IPlist) Init() {
	self.List = make([]*net.IP, 0)
	self.Results = make([]IpCap, 0)
}

func (self *IPlist) AddIP(ip net.IP, wg *sync.WaitGroup) {
	self.Access.Lock()
	defer self.Access.Unlock()
	found := false
	for _, listip := range self.List {
		if ip.Equal(*listip) {
			found = true
			break
		}
	}
	if !found {
		self.List = append(self.List, &ip)
		//wg.Add(1)
		//go self.Capability(ip, wg)
	}
}

func (self *IPlist) Capability(ip net.IP, wg *sync.WaitGroup) {
	defer wg.Done()
	edns0, bind, nsid, dnscookies, err := TestServer(ip.String())
	if err != nil {
		panic(err)
	}
	self.Access.Lock()
	defer self.Access.Unlock()
	// save stats
	self.Results = append(self.Results, IpCap{Ip: ip, EDNS0: edns0, DNSCookies: dnscookies, BINDVERSION: bind, NSID: nsid})
}

func TestServer(server string) (edns0 bool, bind string, nsid string, dnscookies bool, err error) {
	// default answers
	edns0 = false
	bind = ""
	nsid = ""
	dnscookies = false
	err = nil

	// Rate Limit
	ratelimiter <- "x"
	defer func() { _ = <-ratelimiter }()

	// build dns query
	query := new(dns.Msg)
	query.Id = dns.Id()
	query.RecursionDesired = false
	query.AuthenticatedData = true
	query.Question = make([]dns.Question, 1)
	query.Question[0] = dns.Question{Name: "version.bind.", Qtype: dns.TypeTXT, Qclass: dns.ClassCHAOS}
	query.SetEdns0(EDNS0SIZE, false)
	qopt := query.IsEdns0()
	// add nsid
	nsidopt := new(dns.EDNS0_NSID)
	nsidopt.Code = dns.EDNS0NSID
	qopt.Option = append(qopt.Option, nsidopt)
	// add dns cookie
	cookie := new(dns.EDNS0_COOKIE)
	cookie.Code = dns.EDNS0COOKIE
	cookie.Cookie = fmt.Sprintf("%016x", rand.Int63())[:16]
	qopt.Option = append(qopt.Option, cookie)

	// Setting up resolver
	client := new(dns.Client)
	client.ReadTimeout = TIMEOUT

	// make the query and wait for answer
	r, _, err := client.Exchange(query, dnsresolver.Ip2Resolver(server))

	// check for errors
	//if err != nil {
	//	fmt.Printf("%s ", server)
	//	panic(err)
	//}
	if r == nil {
		fmt.Printf("Error: %s\n", err.Error())
		err = nil
		return
	}
	err = nil

	if r.Rcode == dns.RcodeNotImplemented {
		fmt.Printf("Not Implemented\n")
		return
	}
	for _, answer := range r.Answer {
		if answer.Header().Rrtype == dns.TypeTXT {
			bind = strings.Join(answer.(*dns.TXT).Txt, "")
		}
	}

	opt := r.IsEdns0()
	if opt == nil {
		return
	}
	edns0 = true

	// check for NSID and DNS Cookies
	for _, ropt := range opt.Option {
		if ropt.Option() == dns.EDNS0NSID {
			var nsidStr []uint8
			for i := 0; i < len(ropt.(*dns.EDNS0_NSID).Nsid)/2; i++ {
				cNumStr := ropt.(*dns.EDNS0_NSID).Nsid[i*2 : i*2+2]
				cNum, _ := strconv.ParseUint(cNumStr, 16, 8)
				nsidStr = append(nsidStr, uint8(cNum))
			}
			nsid = fmt.Sprintf("%+q", nsidStr)
		}
		if ropt.Option() == dns.EDNS0COOKIE {
			dnscookies = true
		}
	}
	return
}
