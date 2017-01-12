package zonefile

import (
	"os"

	"github.com/miekg/dns"
)

func GetZone(infile string, zone string) <-chan dns.RR {
	// open zone file
	f, err := os.Open(infile)
	if err != nil {
		panic(err)
	}

	// prepare output channel
	out := make(chan dns.RR, 10000)

	// start zone file parsing
	tokens := dns.ParseZone(f, dns.Fqdn(zone), infile)

	// translate tokens to RR and write to output channel
	go func() {
		for token := range tokens {
			if token.Error != nil {
				panic(token.Error)
			}
			out <- token.RR
		}
		f.Close()
		close(out)
	}()

	// return the output channel
	return out
}
