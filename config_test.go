package main

import (
	"flag"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func envLookup(env map[string]string) func(string) (string, bool) {
	return func(key string) (string, bool) {
		value, found := env[key]
		return value, found
	}
}

func TestLoadConfig(t *testing.T) {
	tests := map[string]struct {
		args     []string
		env      map[string]string
		expected Config
	}{
		"defaults": {
			expected: NewConfig(),
		},
		"flags": {
			args: []string{
				"-remote", "flag.example:10011",
				"-user", "flaguser",
				"-password", "flagpassword",
				"-passwordfile", "flagpasswordfile",
				"-listen", "127.0.0.1:1234",
				"-enablechannelmetrics",
				"-ignorefloodlimits",
			},
			expected: Config{
				Remote:               "flag.example:10011",
				ListenAddr:           "127.0.0.1:1234",
				User:                 "flaguser",
				Password:             "flagpassword",
				PasswordFile:         "flagpasswordfile",
				EnableChannelMetrics: true,
				IgnoreFloodLimits:    true,
			},
		},
		"environment": {
			env: map[string]string{
				"REMOTE":                    "env.example:10011",
				"SERVERQUERY_USER":          "envuser",
				"SERVERQUERY_PASSWORD":      "envpassword",
				"SERVERQUERY_PASSWORD_FILE": "envpasswordfile",
				"LISTEN_ADDRESS":            "127.0.0.1:4321",
				"ENABLE_CHANNEL_METRICS":    "1",
				"IGNORE_FLOOD_LIMITS":       "true",
			},
			expected: Config{
				Remote:               "env.example:10011",
				ListenAddr:           "127.0.0.1:4321",
				User:                 "envuser",
				Password:             "envpassword",
				PasswordFile:         "envpasswordfile",
				EnableChannelMetrics: true,
				IgnoreFloodLimits:    true,
			},
		},
		"flags take precedence over the environment": {
			args: []string{"-remote", "flag.example:10011", "-passwordfile", "flagpasswordfile", "-enablechannelmetrics=false"},
			env: map[string]string{
				"REMOTE":                    "env.example:10011",
				"SERVERQUERY_USER":          "envuser",
				"SERVERQUERY_PASSWORD_FILE": "envpasswordfile",
				"ENABLE_CHANNEL_METRICS":    "true",
			},
			expected: Config{
				Remote:               "flag.example:10011",
				ListenAddr:           "0.0.0.0:9189",
				User:                 "envuser",
				PasswordFile:         "flagpasswordfile",
				EnableChannelMetrics: false,
			},
		},
		"invalid boolean environment value falls back to the default": {
			env: map[string]string{"ENABLE_CHANNEL_METRICS": "definitely"},
			expected: Config{
				Remote:               "localhost:10011",
				ListenAddr:           "0.0.0.0:9189",
				User:                 "serveradmin",
				EnableChannelMetrics: false,
			},
		},
		"invalid boolean environment value is still overridden by the flag": {
			args: []string{"-enablechannelmetrics"},
			env:  map[string]string{"ENABLE_CHANNEL_METRICS": "definitely"},
			expected: Config{
				Remote:               "localhost:10011",
				ListenAddr:           "0.0.0.0:9189",
				User:                 "serveradmin",
				EnableChannelMetrics: true,
			},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			fs := flag.NewFlagSet(name, flag.ContinueOnError)
			fs.SetOutput(io.Discard)

			config, err := loadConfig(fs, tc.args, envLookup(tc.env))
			require.Nil(t, err)
			assert.Equal(t, tc.expected, config)
		})
	}
}

func TestLoadConfigParseError(t *testing.T) {
	fs := flag.NewFlagSet("parse error", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	_, err := loadConfig(fs, []string{"-unknown"}, envLookup(nil))
	assert.NotNil(t, err)
}

func TestResolvePassword(t *testing.T) {
	// A password file mode of 0 means no password file is created for the
	// test case and the password file from the config is used as is.
	tests := map[string]struct {
		passwordFileContent string
		passwordFileMode    os.FileMode
		config              Config
		expectedPassword    string
		expectedErr         string
	}{
		"no password file keeps the password": {
			config:           Config{Password: "envpassword"},
			expectedPassword: "envpassword",
		},
		"password file overrides the password": {
			passwordFileContent: "filepassword",
			passwordFileMode:    0600,
			config:              Config{Password: "envpassword"},
			expectedPassword:    "filepassword",
		},
		"surrounding line breaks are trimmed": {
			passwordFileContent: "\r\nfilepassword\r\n",
			passwordFileMode:    0600,
			expectedPassword:    "filepassword",
		},
		"read only password file": {
			passwordFileContent: "filepassword",
			passwordFileMode:    0400,
			expectedPassword:    "filepassword",
		},
		"missing password file": {
			config:      Config{PasswordFile: "testdata/does-not-exist"},
			expectedErr: "failed to get fileinfo of password file",
		},
		"world readable password file": {
			passwordFileContent: "filepassword",
			passwordFileMode:    0644,
			expectedErr:         "password file permissions are too open",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			config := tc.config

			if tc.passwordFileMode != 0 {
				path := filepath.Join(t.TempDir(), "password")
				require.NoError(t, os.WriteFile(path, []byte(tc.passwordFileContent), tc.passwordFileMode))
				require.NoError(t, os.Chmod(path, tc.passwordFileMode))
				config.PasswordFile = path
			}

			err := resolvePassword(&config)

			if tc.expectedErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.expectedErr)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tc.expectedPassword, config.Password)
		})
	}
}
