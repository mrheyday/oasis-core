// Package config implements global configuration options.
package config

// Config is the IAS configuration structure.
type Config struct {
	// IAS proxy address in the form ID@HOST:PORT.
	ProxyAddresses []string `yaml:"proxy_addresses"`

	// Skip IAS AVR signature verification (UNSAFE).
	DebugSkipVerify bool `yaml:"debug_skip_verify,omitempty"`
}

// Validate validates the configuration settings.
func (c *Config) Validate() error {
	return nil
}

// DefaultConfig returns the default configuration settings.
func DefaultConfig() Config {
	return Config{
		ProxyAddresses:  []string{},
		DebugSkipVerify: false,
	}
}
