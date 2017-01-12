package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"

	"github.com/miekg/dns"
	"github.com/ulrichwisser/zonestats/inputs/axfr"
	"github.com/ulrichwisser/zonestats/inputs/zonefile"
	"github.com/ulrichwisser/zonestats/plugins/countdom"
	"github.com/ulrichwisser/zonestats/plugins/countrr"
	"github.com/ulrichwisser/zonestats/plugins/dnssec"
	"github.com/ulrichwisser/zonestats/plugins/nsstats"
)

type Plugin interface {
	Receive(dns.RR, *sync.WaitGroup)
	Stats()
	Done()
	Influx(tld string, source string) string
}

var verbose bool = false
var infile string = ""
var server string = ""
var zone string = ""
var port uint = 53
var resolver string = ""
var influx string = ""
var influxserver, influxport, influxdb string
var source string = ""
var plugins = make([]Plugin, 0)

func main() {
	parseCmdline()
	initPlugins()

	if len(server) > 0 {
		runPlugins(axfr.GetZone(zone, server, port))
	}
	if len(infile) > 0 {
		runPlugins(zonefile.GetZone(infile, zone))
	}

	donePlugins()

	if verbose {
		printStats()
	}
	if len(influx) > 0 {
		runInflux()
	}
}

func parseCmdline() {
	// define and parse command line arguments
	flag.BoolVar(&verbose, "verbose", false, "print more information while running")
	flag.BoolVar(&verbose, "v", false, "print more information while running")
	flag.StringVar(&infile, "infile", "", "filename of zone file")
	flag.StringVar(&server, "axfr", "", "server adress to request axfr")
	flag.StringVar(&zone, "zone", "", "zone for axfr")
	flag.UintVar(&port, "port", 53, "port for axfr")
	flag.StringVar(&resolver, "resolver", "", "resolver name or ip")
	flag.StringVar(&influx, "influx", "", "InfluxDB and port")
	flag.Parse()

	if verbose {
		fmt.Printf("Cmdline: %s --port %d", os.Args[0], port)
		if verbose {
			fmt.Print(" -v")
		}
		if len(infile) > 0 {
			fmt.Printf(" --infile %s", infile)
		}
		if len(server) > 0 {
			fmt.Printf(" --axfr %s", server)
		}
		if len(zone) > 0 {
			fmt.Printf(" --zone %s", zone)
		}
		if len(resolver) > 0 {
			fmt.Printf(" --resolver %s", resolver)
		}
		if len(influx) > 0 {
			fmt.Printf(" --influx %s", influx)
		}
		fmt.Println("")
	}
	if len(server) > 0 && len(infile) > 0 {
		panic(errors.New("Only one of axfr and infile can be given"))
	}
	if len(infile) > 0 {
		source = "file"
	}
	if len(server) > 0 {
		source = "axfr"
	}
	if len(zone) == 0 {
		panic(errors.New("zone must be given"))
	}
	if len(influx) > 0 {
		data := strings.Split(influx, ":")
		if len(data) != 3 {
			panic(errors.New("--influx wrong format! Should be server:port:db"))
		}
		influxserver = data[0]
		influxport = data[1]
		influxdb = data[2]
	}
}

func initPlugins() {
	plugins = append(plugins, countdom.Init())
	plugins = append(plugins, countrr.Init())
	plugins = append(plugins, dnssec.Init())
	plugins = append(plugins, nsstats.Init(zone, []string{resolver}))
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

func printStats() {
	for _, plugin := range plugins {
		plugin.Stats()
	}
}

func runInflux() {
	lines := ""
	for _, plugin := range plugins {
		lines = lines + plugin.Influx(zone, source)
	}
	_, err := http.Post(fmt.Sprintf("http://%s:%s/write?db=%s", influxserver, influxport, influxdb), "application/x-www-form-urlencoded", bytes.NewBufferString(lines))
	if err != nil {
		panic(err)
	}
}
