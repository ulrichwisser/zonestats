package main

import (
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"os/user"
	"path"

	"github.com/ulrichwisser/zonestats/dnsresolver"

	yaml "gopkg.in/yaml.v2"
)

type Configuration struct {
	Dryrun       bool
	Filename     string
	Axfr         string
	Source       string
	Zone         string
	Resolvers    stringslice
	Port         uint
	InfluxServer string
	InfluxDB     string
	InfluxUser   string
	InfluxPasswd string
}

func parseCmdline() *Configuration {
	var config Configuration
	var conffilename string

	// define and parse command line arguments
	flag.StringVar(&conffilename, "conf", "", "Filename to read configuration from")
	flag.BoolVar(&config.Dryrun, "dryrun", false, "Print results instead of writing to InfluxDB")
	flag.StringVar(&config.Filename, "infile", "", "filename of zone file")
	flag.StringVar(&config.Axfr, "axfr", "", "server adress to request axfr")
	flag.StringVar(&config.Zone, "zone", "", "zone for axfr")
	flag.UintVar(&config.Port, "port", 53, "port for axfr")
	flag.Var(&config.Resolvers, "resolver", "resolver name or ip")
	flag.StringVar(&config.InfluxServer, "influxServer", "", "Server with InfluxDB running")
	flag.StringVar(&config.InfluxDB, "influxDB", "", "Name of InfluxDB database")
	flag.StringVar(&config.InfluxUser, "influxUser", "", "Name of InfluxDB user")
	flag.StringVar(&config.InfluxPasswd, "influxPasswd", "", "Name of InfluxDB user password")
	flag.Parse()

	var confFromFile *Configuration
	if conffilename != "" {
		var err error
		confFromFile, err = readConfigFile(conffilename)
		if err != nil {
			panic(err)
		}
	}
	return joinConfig(confFromFile, &config)
}

func readConfigFile(filename string) (config *Configuration, error error) {
	source, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	config = &Configuration{}
	err = yaml.Unmarshal(source, config)
	if err != nil {
		return nil, err
	}
	return config, nil
}

func readDefaultConfigFiles() (config *Configuration) {

	// .dzone in current directory
	usr, err := user.Current()
	if err != nil {
		panic(err)
	}
	fileconfig, err := readConfigFile(path.Join(usr.HomeDir, ".zonestats"))
	if err != nil && !os.IsNotExist(err) {
		panic(err)
	}
	config = joinConfig(config, fileconfig)

	// .dzone in user home directory
	fileconfig, err = readConfigFile(".zonestats")
	if err != nil && !os.IsNotExist(err) {
		panic(err)
	}
	config = joinConfig(config, fileconfig)

	// done
	return
}

func joinConfig(oldConf *Configuration, newConf *Configuration) (config *Configuration) {
	if oldConf == nil && newConf == nil {
		return nil
	}
	if oldConf != nil && newConf == nil {
		return oldConf
	}
	if oldConf == nil && newConf != nil {
		return newConf
	}

	// we have two configs, join them
	config = &Configuration{}
	if newConf.Dryrun || oldConf.Dryrun {
		config.Dryrun = true
	} else {
		config.Dryrun = false
	}
	if newConf.Filename != "" {
		config.Filename = newConf.Filename
	} else {
		config.Filename = oldConf.Filename
	}
	if newConf.Axfr != "" {
		config.Axfr = newConf.Axfr
	} else {
		config.Axfr = oldConf.Axfr
	}
	if newConf.Port != 0 {
		config.Port = newConf.Port
	} else {
		config.Port = oldConf.Port
	}
	if newConf.Zone != "" {
		config.Zone = newConf.Zone
	} else {
		config.Zone = oldConf.Zone
	}
	if newConf.InfluxServer != "" {
		config.InfluxServer = newConf.InfluxServer
	} else {
		config.InfluxServer = oldConf.InfluxServer
	}
	if newConf.InfluxDB != "" {
		config.InfluxDB = newConf.InfluxDB
	} else {
		config.InfluxDB = oldConf.InfluxDB
	}
	if newConf.InfluxUser != "" {
		config.InfluxUser = newConf.InfluxUser
	} else {
		config.InfluxUser = oldConf.InfluxUser
	}
	if newConf.InfluxPasswd != "" {
		config.InfluxPasswd = newConf.InfluxPasswd
	} else {
		config.InfluxPasswd = oldConf.InfluxPasswd
	}

	// Done
	return config
}

func usage() {
	os.Exit(1)
}
func checkConfiguration(config *Configuration) *Configuration {
	// Get resolvers to use
	if len(config.Resolvers) == 0 {
		config.Resolvers = dnsresolver.GetDefaultResolvers()
	}
	if len(config.Resolvers) == 0 {
		fmt.Println("No resolver(s) found.")
		usage()
	}

	if (len(config.Filename) > 0) && (len(config.Axfr) > 0) {
		panic(errors.New("Only one of infile and axfr can be given."))
	}
	if (len(config.Filename) == 0) && (len(config.Axfr) == 0) {
		panic(errors.New("One of infile and axfr must be given."))
	}
	if len(config.Filename) > 0 {
		config.Source = "file"
	}
	if len(config.Axfr) > 0 {
		config.Source = "axfr"
	}
	if config.Port == 0 {
		panic(errors.New("port must be given"))
	}
	if len(config.Zone) == 0 {
		panic(errors.New("zone must be given"))
	}

	// Influx config
	if !config.Dryrun {
		if len(config.InfluxServer) == 0 {
			fmt.Println("Influx server address must be given.")
			usage()
		}
		if len(config.InfluxDB) == 0 {
			fmt.Println("Influx server address must be given.")
			usage()
		}
		if (len(config.InfluxUser) == 0) && (len(config.InfluxPasswd) > 0) {
			fmt.Println("Influx user and password must be given (not only one).")
			usage()
		}
		if (len(config.InfluxUser) > 0) && (len(config.InfluxPasswd) == 0) {
			fmt.Println("Influx user and password must be given (not only one).")
			usage()
		}
	}
	return config
}
