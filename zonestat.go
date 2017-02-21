package main

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sync"

	"github.com/miekg/dns"
	"github.com/ulrichwisser/zonestats/dnsresolver"
	"github.com/ulrichwisser/zonestats/inputs/axfr"
	"github.com/ulrichwisser/zonestats/inputs/zonefile"
	"github.com/ulrichwisser/zonestats/plugins/countdom"
	"github.com/ulrichwisser/zonestats/plugins/countrr"
	"github.com/ulrichwisser/zonestats/plugins/dnssec"
	"github.com/ulrichwisser/zonestats/plugins/nsstats"
)

type Plugin interface {
	Receive(dns.RR, *sync.WaitGroup)
	Done()
	Influx(tld string, source string) string
}

type stringslice []string

func (str *stringslice) String() string {
	return fmt.Sprintf("%s", *str)
}

func (str *stringslice) Set(value string) error {
	*str = append(*str, value)
	return nil
}

var plugins = make([]Plugin, 0)

func main() {
	config := joinConfig(readDefaultConfigFiles(), parseCmdline())
	checkConfiguration(config)
	initPlugins(config)

	if config.Source == "axfr" {
		runPlugins(axfr.GetZone(config.Zone, config.Axfr, config.Port))
	}
	if config.Source == "file" {
		runPlugins(zonefile.GetZone(config.Filename, config.Zone))
	}

	donePlugins()

	runInflux(config)
}

func initPlugins(config *Configuration) {
	plugins = append(plugins, countdom.Init())
	plugins = append(plugins, countrr.Init())
	plugins = append(plugins, dnssec.Init())
	plugins = append(plugins, nsstats.Init(config.Zone, dnsresolver.New(config.Resolvers)))
	//plugins = append(plugins, unregns.Init())
}

func runPlugins(rrlist <-chan dns.RR) {
	var wg sync.WaitGroup
	for rr := range rrlist {
		for _, plugin := range plugins {
			wg.Add(1)
			go plugin.Receive(rr, &wg)
		}
	}
	wg.Wait()
}

func donePlugins() {
	for _, plugin := range plugins {
		plugin.Done()
	}
}

func runInflux(config *Configuration) {

	// collect line data
	lines := ""
	for _, plugin := range plugins {
		lines = lines + plugin.Influx(config.Zone, config.Source)
	}

	// compute InfluxDB URL
	sessionurl, err := url.Parse(config.InfluxServer)
	sessionurl.Path = "write"
	q := sessionurl.Query()
	q.Set("db", config.InfluxDB)
	sessionurl.RawQuery = q.Encode()

	req, err := http.NewRequest(http.MethodPost, sessionurl.String(), bytes.NewBufferString(lines))
	if err != nil {
		panic(err)
	}
	if len(config.InfluxUser) > 0 {
		req.SetBasicAuth(config.InfluxUser, config.InfluxPasswd)
	}

	if !config.Dryrun {
		_, err = http.DefaultClient.Do(req)
		if err != nil {
			panic(err)
		}
	} else {
		fmt.Println("DRYRUN! No actual call to InfluxDB has been made. The following call would have been made without --dryrun")
		requestDump, err := httputil.DumpRequest(req, true)
		if err != nil {
			fmt.Println(err)
		}
		fmt.Println(string(requestDump))

		//		fmt.Printf("http://%s:%s/write?db=%s\n", config.InfluxServer, config.InfluxPort, config.InfluxDB)
		//		if len(config.InfluxUser) > 0 {
		//			auth := config.InfluxUser + ":" + config.InfluxPasswd
		//			fmt.Printf("Authorization: %s\n", base64.StdEncoding.EncodeToString([]byte(auth)))
		//		}
		//		fmt.Println(lines)
	}
}
