package cybersource_soap_dm

import (
	"fmt"
	"os"

	"github.com/joho/godotenv"
)

// Environment represents the CyberSource environment (sandbox or production).
type Environment string

const (
	EnvSandbox    Environment = "sandbox"
	EnvProduction Environment = "production"
)

// Config holds the credentials and settings needed to interact with
// the CyberSource Decision Manager SOAP API.
type Config struct {
	// MerchantID is the CyberSource merchant identifier.
	MerchantID string

	// P12Path is the filesystem path to the P12/PFX certificate file
	// used for WS-Security BinarySecurityToken + XML digital signature.
	P12Path string

	// P12Password is the password that protects the P12 file.
	P12Password string

	// Env selects sandbox or production endpoints.
	Env Environment

	// BaseURL optionally overrides the SOAP endpoint URL.
	// When empty, the URL is derived from Env.
	BaseURL string
}

// Validate checks that the required configuration fields are present.
func (c Config) Validate() error {
	if c.MerchantID == "" {
		return fmt.Errorf("cybersource_soap_dm: MerchantID is required")
	}
	if c.P12Path == "" {
		return fmt.Errorf("cybersource_soap_dm: P12Path is required")
	}
	return nil
}

// DefaultBaseURL returns the SOAP transaction endpoint for the configured environment.
func (c Config) DefaultBaseURL() string {
	if c.BaseURL != "" {
		return c.BaseURL
	}
	if c.Env == EnvProduction {
		return "https://ics2ws.ic3.com/commerce/1.x/transactionProcessor"
	}
	return "https://ics2wstest.ic3.com/commerce/1.x/transactionProcessor"
}

// LoadConfigFromEnv creates a Config from environment variables:
//
//	CYBS_DM_MERCHANT_ID   – merchant identifier (required)
//	CYBS_DM_P12_PATH      – path to P12 certificate file (required)
//	CYBS_DM_P12_PASSWORD  – P12 file password
//	CYBS_DM_ENV           – "sandbox" (default) or "production"
//	CYBS_DM_BASE_URL      – optional SOAP endpoint override
func LoadConfigFromEnv() Config {
	return configFromEnv()
}

// LoadConfigFromDotEnv loads environment variables from a .env file and then
// reads the Config from them. If the file does not exist it silently falls
// back to the current process environment.
func LoadConfigFromDotEnv(filenames ...string) Config {
	// godotenv.Load does NOT override existing env vars.
	_ = godotenv.Load(filenames...)
	return configFromEnv()
}

func configFromEnv() Config {
	env := EnvSandbox
	if os.Getenv("CYBS_DM_ENV") == "production" {
		env = EnvProduction
	}

	return Config{
		MerchantID:  os.Getenv("CYBS_DM_MERCHANT_ID"),
		P12Path:     os.Getenv("CYBS_DM_P12_PATH"),
		P12Password: os.Getenv("CYBS_DM_P12_PASSWORD"),
		Env:         env,
		BaseURL:     os.Getenv("CYBS_DM_BASE_URL"),
	}
}
