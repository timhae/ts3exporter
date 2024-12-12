package main

import (
	"flag"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/wittdennis/ts3exporter/pkg/collector"

	"github.com/wittdennis/ts3exporter/pkg/serverquery"
)

func main() {
	config := NewConfig()
	setConfig(&config)

	flag.Parse()

	fInfo, err := os.Stat(config.PasswordFile)
	if err != nil {
		log.Fatalf("failed to get fileinfo of password file: %v\n", err)
	}
	if !(fInfo.Mode() == 0600 || fInfo.Mode() == 0400) {
		log.Fatalf("password file permissions are to open. Have: %s, want at most: %o\n", fInfo.Mode().String(), 0600)
	}
	data, err := os.ReadFile(config.PasswordFile)
	if err != nil {
		log.Fatalf("failed to read password file: %v\n", err)
	}
	config.Password = strings.Trim(string(data), "\r\n")

	c, err := serverquery.NewClient(config.Remote, config.User, config.Password, config.IgnoreFloodLimits)
	if err != nil {
		log.Fatalf("failed to init client %v\n", err)
	}
	internalMetrics := collector.NewExporterMetrics()
	seq := collector.SequentialCollector{collector.NewServerInfo(c, internalMetrics)}

	if config.EnableChannelMetrics {
		cInfo := collector.NewChannel(c, internalMetrics)
		seq = append(seq, cInfo)
	}

	prometheus.MustRegister(append(seq, collector.NewClient(c)))
	// The Handler function provides a default handler to expose metrics
	// via an HTTP server. "/metrics" is the usual endpoint for that.
	http.Handle("/metrics", promhttp.Handler())
	log.Fatal(http.ListenAndServe(config.ListenAddr, nil))
}

func setConfig(config *Config) {
	if remote, found := os.LookupEnv("REMOTE"); found {
		config.Remote = remote
	} else {
		flag.StringVar(&config.Remote, "remote", "localhost:10011", "remote address of server query port")
	}

	if user, found := os.LookupEnv("SERVERQUERY_USER"); found {
		config.User = user
	} else {
		flag.StringVar(&config.User, "user", "serveradmin", "the serverquery user of the ts3exporter")
	}

	if pwf, found := os.LookupEnv("SERVERQUERY_PASSWORD_FILE"); found {
		config.PasswordFile = pwf
	} else {
		flag.StringVar(&config.PasswordFile, "passwordfile", "", "The password file for the serverquery user")
	}

	if pw, found := os.LookupEnv("SERVERQUERY_PASSWORD"); found {
		config.Password = pw
	} else {
		flag.StringVar(&config.Password, "password", "", "The password for the serverquery user")
	}

	if listen, found := os.LookupEnv("LISTEN_ADDRESS"); found {
		config.ListenAddr = listen
	} else {
		flag.StringVar(&config.ListenAddr, "listen", "0.0.0.0:9189", "listen address of the exporter")
	}

	if enableChannelMetrics, found := os.LookupEnv("ENABLE_CHANNEL_METRICS"); found {
		v, err := strconv.ParseBool(enableChannelMetrics)
		if err != nil {
			config.EnableChannelMetrics = false
		} else {
			config.EnableChannelMetrics = v
		}
	} else {
		flag.BoolVar(&config.EnableChannelMetrics, "enablechannelmetrics", false, "Enables the channel collector.")
	}

	if ignoreFloodLimits, found := os.LookupEnv("IGNORE_FLOOD_LIMITS"); found {
		v, err := strconv.ParseBool(ignoreFloodLimits)
		if err != nil {
			config.IgnoreFloodLimits = false
		} else {
			config.IgnoreFloodLimits = v
		}
	} else {
		flag.BoolVar(&config.IgnoreFloodLimits, "ignorefloodlimits", false, "Disable the server query flood limiter. Use this only if your exporter is whitelisted in the query_ip_whitelist.txt file.")
	}
}
