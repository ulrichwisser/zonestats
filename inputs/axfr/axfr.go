package axfr

import (
	"fmt"
	"strings"
	"time"

	"github.com/miekg/dns"
)

func GetZone(zone string, server string, port uint) <-chan dns.RR {

	// Setting up transfer
	transfer := &dns.Transfer{DialTimeout: 5 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second}

	// Setting up query
	query := new(dns.Msg)
	query.RecursionDesired = true
	query.Question = make([]dns.Question, 1)
	query.SetQuestion(dns.Fqdn(zone), dns.TypeAXFR)

	// add port
	if strings.ContainsAny(":", server) {
		// IPv6 address
		server = fmt.Sprintf("[%s]:%d", server, port)
	} else {
		server = fmt.Sprintf("%s:%d", server, port)
	}

	// start transfer
	channel, err := transfer.In(query, server)
	if err != nil {
		panic(err)
	}

	// prepare output channel
	c := make(chan dns.RR, 100)

	// translate transfer Envelope to dns.RR
	go func() {
		for env := range channel {
			if env.Error != nil {
				panic(env.Error)
			}
			for _, rr := range env.RR {
				c <- rr
			}
		}
		close(c)
	}()

	// return
	return c
}
