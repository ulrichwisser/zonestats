package dnsresolver

import (
	"errors"
	"fmt"
	"math/rand"
	"os"
	"strings"
	"time"

	"github.com/miekg/dns"
)

const (
	TIMEOUT   time.Duration = 5 * time.Second
	RATELIMIT uint          = 100
)

var ratelimiter = make(chan string, RATELIMIT)

type Resolver struct {
	resolvers []string
}

func New(resolvers []string) *Resolver {
	self := Resolver{}
	self.resolvers = make([]string, 0)
	if len(resolvers) > 0 {
		for _, resolver := range resolvers {
			self.resolvers = append(self.resolvers, Ip2Resolver(resolver))
		}
	} else {
		self.resolvers = GetDefaultResolvers()
	}
	return &self
}

// resolv will send a query and return the result
func (self *Resolver) Resolv(qname string, qtype uint16) []dns.RR {
	ratelimiter <- "x"
	defer func() { _ = <-ratelimiter }()

	// Setting up query
	query := new(dns.Msg)
	query.RecursionDesired = true
	query.Question = make([]dns.Question, 1)
	query.SetQuestion(qname, qtype)

	// Setting up resolver
	client := new(dns.Client)
	client.ReadTimeout = TIMEOUT

	// decide on which resolver to use
	server := self.resolvers[rand.Intn(len(self.resolvers))]

	// make the query and wait for answer
	r, _, err := client.Exchange(query, server)

	// check for errors
	if err != nil {
		//fmt.Printf("%-30s: Error resolving %s (server %s)\n", domain, err, server)
		return nil
	}
	if r == nil {
		//fmt.Printf("%-30s: No answer (Server %s)\n", domain, server)
		return nil
	}
	if r.Rcode != dns.RcodeSuccess {
		//fmt.Printf("%-30s: %s (Rcode %d, Server %s)\n", domain, rcode2string[r.Rcode], r.Rcode, server)
		return nil
	}

	return r.Answer
}

func Ip2Resolver(server string) string {
	if strings.ContainsAny(":", server) {
		// IPv6 address
		server = "[" + server + "]:53"
	} else {
		server = server + ":53"
	}
	return server
}

// getResolvers will read the list of resolvers from /etc/resolv.conf
func GetDefaultResolvers() []string {
	resolvers := make([]string, 0)
	conf, err := dns.ClientConfigFromFile("/etc/resolv.conf")
	if err != nil {
		panic(err)
	}
	if conf == nil {
		panic(errors.New(fmt.Sprintf("Cannot initialize the local resolver: %s\n", err)))
	}
	for i := range conf.Servers {
		resolvers = append(resolvers, conf.Servers[i])
	}
	if len(resolvers) == 0 {
		fmt.Println("No resolvers found.")
		os.Exit(5)
	}
	return resolvers
}
