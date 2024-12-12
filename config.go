package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
)

type Config struct {
	Remote               string
	ListenAddr           string
	User                 string
	Password             string
	PasswordFile         string
	EnableChannelMetrics bool
	IgnoreFloodLimits    bool
}

func NewConfig() Config {
	config := Config{}
	config.Remote = "localhost:10011"
	config.ListenAddr = "0.0.0.0:9189"
	config.User = "serveradmin"
	config.Password = ""
	config.PasswordFile = ""
	config.EnableChannelMetrics = false
	config.IgnoreFloodLimits = false

	return config
}

// loadConfig resolves the configuration in the following order, from highest to
// lowest priority:
//   - command-line flags
//   - environment variables
//   - defaults from NewConfig
//
// The flag set, arguments and environment lookup are passed in so that the
// resolution can be tested without touching the process globals.
func loadConfig(fs *flag.FlagSet, args []string, lookupEnv func(string) (string, bool)) (Config, error) {
	config := NewConfig()

	envString(lookupEnv, "REMOTE", &config.Remote)
	envString(lookupEnv, "SERVERQUERY_USER", &config.User)
	envString(lookupEnv, "SERVERQUERY_PASSWORD_FILE", &config.PasswordFile)
	envString(lookupEnv, "SERVERQUERY_PASSWORD", &config.Password)
	envString(lookupEnv, "LISTEN_ADDRESS", &config.ListenAddr)
	envBool(lookupEnv, "ENABLE_CHANNEL_METRICS", &config.EnableChannelMetrics)
	envBool(lookupEnv, "IGNORE_FLOOD_LIMITS", &config.IgnoreFloodLimits)

	// The already resolved values act as the flag defaults, so an unset flag
	// keeps the environment value while an explicit flag overrides it.
	fs.StringVar(&config.Remote, "remote", config.Remote, "Remote address of server query port.")
	fs.StringVar(&config.User, "user", config.User, "The serverquery user of the ts3exporter.")
	fs.StringVar(&config.PasswordFile, "passwordfile", config.PasswordFile, "The password file for the serverquery user.")
	fs.StringVar(&config.Password, "password", config.Password, "The password for the serverquery user.")
	fs.StringVar(&config.ListenAddr, "listen", config.ListenAddr, "Listen address of the exporter.")
	fs.BoolVar(&config.EnableChannelMetrics, "enablechannelmetrics", config.EnableChannelMetrics, "Enables the channel collector.")
	fs.BoolVar(&config.IgnoreFloodLimits, "ignorefloodlimits", config.IgnoreFloodLimits, "Disable the server query flood limiter. Use this only if your exporter is whitelisted in the query_ip_whitelist.txt file.")

	if err := fs.Parse(args); err != nil {
		return config, err
	}

	return config, nil
}

// resolvePassword reads the password from the password file if one is
// configured. The password file takes precedence over the password from the
// command-line flags and environment variables. The file must have 0600 or
// 0400 permissions so the password is not exposed to other users.
func resolvePassword(config *Config) error {
	if config.PasswordFile == "" {
		return nil
	}

	info, err := os.Stat(config.PasswordFile)
	if err != nil {
		return fmt.Errorf("failed to get fileinfo of password file: %w", err)
	}
	if info.Mode() != 0600 && info.Mode() != 0400 {
		return fmt.Errorf("password file permissions are too open. Have: %s, want at most: %o", info.Mode().String(), 0600)
	}

	data, err := os.ReadFile(config.PasswordFile)
	if err != nil {
		return fmt.Errorf("failed to read password file: %w", err)
	}

	config.Password = strings.Trim(string(data), "\r\n")
	return nil
}

func envString(lookupEnv func(string) (string, bool), key string, target *string) {
	if value, found := lookupEnv(key); found {
		*target = value
	}
}

func envBool(lookupEnv func(string) (string, bool), key string, target *bool) {
	value, found := lookupEnv(key)
	if !found {
		return
	}

	parsed, err := strconv.ParseBool(value)
	if err != nil {
		log.Printf("ignoring invalid boolean value %q for %s\n", value, key)
		return
	}

	*target = parsed
}
