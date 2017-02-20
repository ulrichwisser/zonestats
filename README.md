# zonestats

Zonestats is a tool to take statistics on a DNS zone.
The zone can be obtained through a zone file or through axfr from an authorative name server.

## Installation

```
$ go get -u github.com/ulrichwisser/zonestats
```

## Configuration
Zonestats will read first $HOME/.zonestats then it will read ./.zonestats. Next the config file given at the command line (if any) will be read and finally the command line arguments will be parsed. All these configurations will be joined together. Information which is read later overwrites any information from previous configuration.

The configuration files have to be in YAML format.
```
filename: zonefile
axfr: nameserver of example.com
zone: example.com
resolvers: 
  - 127.0.0.1
  - 127.0.0.2
  - ::1
influxserver: 127.0.0.1
influxport: 8086
influxdb: databasename
influxuser: username
influxpasswd: password
```

## Command Line Parameters
```
--dryrun                     run all statistics but do not write to InfluxDB (write data to STDOUT instead)
--conf <filename>            file to read configuration
--zone <zone>                name of the zone to run statistics for
--infile <zonefile>          name of the zone file
--axfr <server>              name or ip of the server for axfr
--resolvers <ip>             ip address of an resolver to use
--influxServer <server>      name or ip of the server running InfluxDB
--influxPort <port>          port number InfluxDB is running on
--influxDB <dbname>          name of the database to save statistics to
--influxUser <username>      username for authorization to InfluxDB
--influxPasswd <password>    password for authorization to InfluxDB
```
## Limitations
- Currently AXFR with TSIG is not supported
