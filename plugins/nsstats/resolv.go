package nsstats

import (
	"time"

	"github.com/miekg/dns"
)

const (
	TIMEOUT   time.Duration = 5 * time.Second
	RATELIMIT uint          = 200
)

var ratelimiter = make(chan string, RATELIMIT)

// resolv will send a query and return the result
func resolv(qname string, qtype uint16, server string) []dns.RR {
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
