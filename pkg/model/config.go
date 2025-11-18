package model

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"vc/pkg/logger"
	"vc/pkg/oauth2"
	"vc/pkg/openid4vci"
	"vc/pkg/pki"
	"vc/pkg/sdjwt3"

	"gopkg.in/yaml.v2"
)

// APIServer holds the api server configuration
type APIServer struct {
	Addr         string            `yaml:"addr" validate:"required"`
	ExternalPort string            `yaml:"external_port,omitempty" validate:"omitempty"`
	PublicKeys   map[string]string `yaml:"public_keys"`
	TLS          TLS               `yaml:"tls" validate:"omitempty"`
	BasicAuth    BasicAuth         `yaml:"basic_auth"`
}

// TLS holds the tls configuration
type TLS struct {
	Enabled      bool   `yaml:"enabled"`
	CertFilePath string `yaml:"cert_file_path" validate:"required"`
	KeyFilePath  string `yaml:"key_file_path" validate:"required"`
}

// Mongo holds the database configuration
type Mongo struct {
	URI string `yaml:"uri" validate:"required"`
}

// Kafka holds the kafka configuration that is common for the entire system
type Kafka struct {
	Enabled bool     `yaml:"enabled"`
	Brokers []string `yaml:"brokers" validate:"required"`
}

// Log holds the log configuration
type Log struct {
	Level      string `yaml:"level"`
	FolderPath string `yaml:"folder_path"`
}

// Common holds the common configuration
type Common struct {
	HTTPProxy       string                `yaml:"http_proxy"`
	Production      bool                  `yaml:"production"`
	Log             Log                   `yaml:"log"`
	Mongo           Mongo                 `yaml:"mongo" validate:"omitempty"`
	Tracing         OTEL                  `yaml:"tracing" validate:"required"`
	Kafka           Kafka                 `yaml:"kafka" validate:"omitempty"`
	CredentialOffer CredentialOfferConfig `yaml:"credential_offer" validate:"omitempty"`
}

type CredentialOfferConfig struct {
	// WalletURL sets the wallet url or "openid-credential-offer://"
	WalletURL string `yaml:"wallet_url"`
	IssuerURL string `yaml:"issuer_url" validate:"required"`
	Type      string `yaml:"type" validate:"required,oneof=credential_offer_uri credential_offer"`
	QR        QRCfg  `yaml:"qr" validate:"omitempty"`
}

// QRCfg holds the qr configuration
type QRCfg struct {
	RecoveryLevel int `yaml:"recovery_level" validate:"required,min=0,max=3"`
	Size          int `yaml:"size" validate:"required"`
}

// SMT Spares Merkel Tree configuration
type SMT struct {
	UpdatePeriodicity int    `yaml:"update_periodicity" validate:"required"`
	InitLeaf          string `yaml:"init_leaf" validate:"required"`
}

// GRPCServer holds the rpc configuration
type GRPCServer struct {
	Addr     string `yaml:"addr" validate:"required"`
	Insecure bool   `yaml:"insecure"`
}

// PDF holds the pdf configuration (special Ladok case)
type PDF struct {
	KeepSignedDuration   int `yaml:"keep_signed_duration"`
	KeepUnsignedDuration int `yaml:"keep_unsigned_duration"`
}

// JWTAttribute holds the jwt attribute configuration.
// In a later state this should be placed under authentic source in order to issue credentials based on that configuration.
type JWTAttribute struct {
	// Issuer of the token example: https://issuer.sunet.se
	Issuer string `yaml:"issuer" validate:"required"`

	// StaticHost is the static host of the issuer, expose static files, like pictures
	StaticHost string `yaml:"static_host" validate:"omitempty"`

	// EnableNotBefore states the time not before which the token is valid
	EnableNotBefore bool `yaml:"enable_not_before"`

	// Valid duration of the token in seconds
	ValidDuration int64 `yaml:"valid_duration" validate:"required_with=EnableNotBefore"`

	// VerifiableCredentialType URL example: https://credential.sunet.se/identity_credential
	VerifiableCredentialType string `yaml:"verifiable_credential_type" validate:"required"`

	// Status status of the Verifiable Credential
	Status string `yaml:"status"`

	// Kid key id of the signing key
	Kid string `yaml:"kid"`
}

// SAMLConfig holds SAML Service Provider configuration for the issuer
type SAMLConfig struct {
	// Enabled turns on SAML support (default: false)
	Enabled bool `yaml:"enabled"`

	// EntityID is the SAML SP entity identifier (typically the metadata URL)
	EntityID string `yaml:"entity_id" validate:"required_if=Enabled true"`

	// MetadataURL is the public URL where SP metadata is served (optional, auto-generated if empty)
	MetadataURL string `yaml:"metadata_url,omitempty"`

	// MDQServer is the base URL for MDQ (Metadata Query Protocol) server
	// Example: "https://md.example.org/entities/" (must end with /)
	MDQServer string `yaml:"mdq_server" validate:"required_if=Enabled true"`

	// CertificatePath is the path to X.509 certificate for SAML signing/encryption
	CertificatePath string `yaml:"certificate_path" validate:"required_if=Enabled true"`

	// PrivateKeyPath is the path to private key for SAML signing/encryption
	PrivateKeyPath string `yaml:"private_key_path" validate:"required_if=Enabled true"`

	// ACSEndpoint is the Assertion Consumer Service URL where IdP sends SAML responses
	// Example: "https://issuer.example.com/saml/acs"
	ACSEndpoint string `yaml:"acs_endpoint" validate:"required_if=Enabled true"`

	// SessionDuration in seconds (default: 3600)
	SessionDuration int `yaml:"session_duration"`

	// CredentialMappings defines how to map external attributes to credential claims
	// Key: credential type identifier (e.g., "pid", "diploma")
	// Maps to credential_constructor keys and OpenID4VCI credential_configuration_ids
	CredentialMappings map[string]CredentialMapping `yaml:"credential_mappings" validate:"required_if=Enabled true"`

	// MetadataCacheTTL in seconds (default: 3600) - how long to cache IdP metadata from MDQ
	MetadataCacheTTL int `yaml:"metadata_cache_ttl"`
}

// CredentialMapping defines how to issue a specific credential type via SAML
// The credential type identifier (map key) is used in API requests and session state
type CredentialMapping struct {
	// CredentialConfigID is the OpenID4VCI credential configuration identifier
	// Example: "urn:eudi:pid:1"
	CredentialConfigID string `yaml:"credential_config_id" validate:"required"`

	// Attributes maps SAML attribute OIDs to claim paths with transformation rules
	// Example: "urn:oid:2.5.4.42" -> {claim: "identity.given_name", required: true}
	Attributes map[string]AttributeConfig `yaml:"attributes" validate:"required"`

	// DefaultIdP is the optional default IdP entityID for this credential type
	DefaultIdP string `yaml:"default_idp,omitempty"`
}

// AttributeConfig defines how a single external attribute maps to a credential claim
// Generic across protocols (SAML, OIDC, etc.) - uses protocol-specific identifiers as keys
type AttributeConfig struct {
	// Claim is the target claim name (supports dot-notation for nesting)
	// Example: "given_name" or "identity.given_name"
	Claim string `yaml:"claim" validate:"required"`

	// Required indicates if this attribute must be present in the assertion/response
	Required bool `yaml:"required"`

	// Transform is an optional transformation to apply
	// Supported: "lowercase", "uppercase", "trim"
	Transform string `yaml:"transform,omitempty" validate:"omitempty,oneof=lowercase uppercase trim"`

	// Default is an optional default value if attribute is missing
	Default string `yaml:"default,omitempty"`
}

// Issuer holds the issuer configuration
type Issuer struct {
	APIServer      APIServer    `yaml:"api_server" validate:"required"`
	Identifier     string       `yaml:"identifier" validate:"required"`
	GRPCServer     GRPCServer   `yaml:"grpc_server" validate:"required"`
	SigningKeyPath string       `yaml:"signing_key_path" validate:"required"`
	JWTAttribute   JWTAttribute `yaml:"jwt_attribute" validate:"required"`
	IssuerURL      string       `yaml:"issuer_url" validate:"required"`
	WalletURL      string       `yaml:"wallet_url"`
	SAML           SAMLConfig   `yaml:"saml,omitempty" validate:"omitempty"`
}

// Registry holds the registry configuration
type Registry struct {
	APIServer  APIServer  `yaml:"api_server" validate:"required"`
	SMT        SMT        `yaml:"smt" validate:"required"`
	GRPCServer GRPCServer `yaml:"grpc_server" validate:"required"`
}

// Persistent holds the persistent storage configuration
type Persistent struct {
	APIServer APIServer `yaml:"api_server" validate:"required"`
}

// MockAS holds the mock as configuration
type MockAS struct {
	APIServer      APIServer `yaml:"api_server" validate:"required"`
	DatastoreURL   string    `yaml:"datastore_url" validate:"required"`
	BootstrapUsers []string  `yaml:"bootstrap_users"`
}

// Verifier holds the verifier configuration
type Verifier struct {
	APIServer         APIServer         `yaml:"api_server" validate:"required"`
	GRPCServer        GRPCServer        `yaml:"grpc_server" validate:"required"`
	ExternalServerURL string            `yaml:"external_server_url" validate:"required"`
	OAuthServer       OAuthServer       `yaml:"oauth_server" validate:"omitempty"`
	IssuerMetadata    IssuerMetadata    `yaml:"issuer_metadata" validate:"omitempty"`
	SupportedWallets  map[string]string `yaml:"supported_wallets" validate:"omitempty"`
}

// VerifierProxy holds the verifier proxy configuration
type VerifierProxy struct {
	APIServer   APIServer       `yaml:"api_server" validate:"required"`
	ExternalURL string          `yaml:"external_url" validate:"required"`
	OIDC        OIDCConfig      `yaml:"oidc" validate:"required"`
	OpenID4VP   OpenID4VPConfig `yaml:"openid4vp" validate:"required"`
}

// OIDCConfig holds OIDC-specific configuration for the verifier-proxy's role as an OpenID Provider.
// This configures how the verifier-proxy issues ID tokens and access tokens to relying parties.
// Note: This is NOT related to verifiable credential issuance (see IssuerConfig for VC issuance).
type OIDCConfig struct {
	// Issuer is the OIDC Provider identifier that appears in ID tokens and discovery metadata.
	// This identifies the verifier-proxy itself as an OpenID Provider.
	// Must match the 'iss' claim in all issued ID tokens.
	Issuer               string `yaml:"issuer" validate:"required"`
	SigningKeyPath       string `yaml:"signing_key_path" validate:"required"`
	SigningAlg           string `yaml:"signing_alg" validate:"required,oneof=RS256 RS384 RS512 ES256 ES384 ES512"`
	SessionDuration      int    `yaml:"session_duration" validate:"required"`       // in seconds
	CodeDuration         int    `yaml:"code_duration" validate:"required"`          // in seconds
	AccessTokenDuration  int    `yaml:"access_token_duration" validate:"required"`  // in seconds
	IDTokenDuration      int    `yaml:"id_token_duration" validate:"required"`      // in seconds
	RefreshTokenDuration int    `yaml:"refresh_token_duration" validate:"required"` // in seconds
	SubjectType          string `yaml:"subject_type" validate:"required,oneof=public pairwise"`
	SubjectSalt          string `yaml:"subject_salt" validate:"required"`
}

// OpenID4VPConfig holds OpenID4VP-specific configuration
type OpenID4VPConfig struct {
	PresentationTimeout     int                         `yaml:"presentation_timeout" validate:"required"`
	SupportedCredentials    []SupportedCredentialConfig `yaml:"supported_credentials" validate:"required"`
	PresentationRequestsDir string                      `yaml:"presentation_requests_dir,omitempty"` // Optional: directory with presentation request templates
}

// SupportedCredentialConfig maps credential types to OIDC scopes
type SupportedCredentialConfig struct {
	VCT    string   `yaml:"vct" validate:"required"`
	Scopes []string `yaml:"scopes" validate:"required"`
}

// Datastore holds the datastore configuration
type Datastore struct {
	APIServer  APIServer  `yaml:"api_server" validate:"required"`
	GRPCServer GRPCServer `yaml:"grpc_server" validate:"required"`
}

// BasicAuth holds the basic auth configuration
type BasicAuth struct {
	Users   map[string]string `yaml:"users"`
	Enabled bool              `yaml:"enabled"`
}

type IssuerMetadata struct {
	Path             string `yaml:"path" validate:"required"`
	SigningKeyPath   string `yaml:"signing_key_path" validate:"required"`
	SigningChainPath string `yaml:"signing_chain_path" validate:"required"`
}

type CredentialOfferWallets struct {
	Label       string `yaml:"label" validate:"required"`
	RedirectURI string `yaml:"redirect_uri" validate:"required"`
}

type CredentialOffers struct {
	IssuerURL string                            `yaml:"issuer_url" validate:"required"`
	Wallets   map[string]CredentialOfferWallets `yaml:"wallets" validate:"required"`
}

// APIGW holds the datastore configuration
type APIGW struct {
	APIServer         APIServer        `yaml:"api_server" validate:"required"`
	CredentialOffers  CredentialOffers `yaml:"credential_offers" validate:"omitempty"`
	OauthServer       OAuthServer      `yaml:"oauth_server" validate:"omitempty"`
	IssuerMetadata    IssuerMetadata   `yaml:"issuer_metadata" validate:"omitempty"`
	ExternalServerURL string           `yaml:"external_server_url" validate:"required"`
}

// OTEL holds the opentelemetry configuration
type OTEL struct {
	Addr    string `yaml:"addr" validate:"required"`
	Type    string `yaml:"type" validate:"required"`
	Timeout int64  `yaml:"timeout" default:"10"`
}

// OAuthServer holds the oauth server configuration
type OAuthServer struct {
	TokenEndpoint string         `yaml:"token_endpoint" validate:"required"`
	Clients       oauth2.Clients `yaml:"clients" validate:"required"`
	Metadata      OAuthMetadata  `yaml:"metadata" validate:"required"`
}

type OAuthMetadata struct {
	Path             string `yaml:"path" validate:"required"`
	SigningKeyPath   string `yaml:"signing_key_path" validate:"required"`
	SigningChainPath string `yaml:"signing_chain_path" validate:"required"`
}

// UI holds the user-interface configuration
type UI struct {
	APIServer                         APIServer `yaml:"api_server" validate:"required"`
	Username                          string    `yaml:"username" validate:"required"`
	Password                          string    `yaml:"password" validate:"required"`
	SessionCookieAuthenticationKey    string    `yaml:"session_cookie_authentication_key" validate:"required"`
	SessionStoreEncryptionKey         string    `yaml:"session_store_encryption_key" validate:"required"`
	SessionInactivityTimeoutInSeconds int       `yaml:"session_inactivity_timeout_in_seconds" validate:"required"`
	Services                          struct {
		APIGW struct {
			BaseURL string `yaml:"base_url"`
		} `yaml:"apigw"`
		MockAS struct {
			BaseURL string `yaml:"base_url"`
		} `yaml:"mockas"`
		Verifier struct {
			BaseURL string `yaml:"base_url"`
		} `yaml:"verifier"`
	} `yaml:"services"`
}

// CredentialType holds the configuration for the credential type
type CredentialType struct {
	Profile string `yaml:"profile" validate:"required"`
}

// NotificationEndpoint holds the configuration for the notification endpoint
type NotificationEndpoint struct {
	URL string `yaml:"url" validate:"required"`
}

// AuthenticSourceEndpoint holds the configuration for the authentic source
type AuthenticSourceEndpoint struct {
	URL string `yaml:"url" validate:"required"`
}

// SignatureServiceEndpoint holds the configuration for the signature service
type SignatureServiceEndpoint struct {
	URL string `yaml:"url" validate:"required"`
}

// RevocationServiceEndpoint holds the configuration for the revocation service
type RevocationServiceEndpoint struct {
	URL string `yaml:"url" validate:"required"`
}

// AuthenticSource holds the configuration for the authentic source
type AuthenticSource struct {
	CountryCode               string                    `yaml:"country_code" validate:"required,iso3166_1_alpha2"`
	NotificationEndpoint      NotificationEndpoint      `yaml:"notification_endpoint" validate:"required"`
	AuthenticSourceEndpoint   AuthenticSourceEndpoint   `yaml:"authentic_source_endpoint" validate:"required"`
	SignatureServiceEndpoint  SignatureServiceEndpoint  `yaml:"signature_service_endpoint" validate:"required"`
	RevocationServiceEndpoint RevocationServiceEndpoint `yaml:"revocation_service_endpoint" validate:"required"`
	CredentialTypes           map[string]CredentialType `yaml:"credential_types" validate:"required"`
}

// Cfg is the main configuration structure for this application
type Cfg struct {
	Common                Common                            `yaml:"common"`
	AuthenticSources      map[string]AuthenticSource        `yaml:"authentic_sources" validate:"omitempty"`
	APIGW                 APIGW                             `yaml:"apigw" validate:"omitempty"`
	Issuer                Issuer                            `yaml:"issuer" validate:"omitempty"`
	Verifier              Verifier                          `yaml:"verifier" validate:"omitempty"`
	VerifierProxy         VerifierProxy                     `yaml:"verifier_proxy" validate:"omitempty"`
	Datastore             Datastore                         `yaml:"datastore" validate:"omitempty"`
	Registry              Registry                          `yaml:"registry" validate:"omitempty"`
	Persistent            Persistent                        `yaml:"persistent" validate:"omitempty"`
	MockAS                MockAS                            `yaml:"mock_as" validate:"omitempty"`
	UI                    UI                                `yaml:"ui" validate:"omitempty"`
	CredentialConstructor map[string]*CredentialConstructor `yaml:"credential_constructor" validate:"omitempty"`
}

// GetCredentialConstructorAuthMethod returns the auth method for the given credential type or "basic" if not found
func (c *Cfg) GetCredentialConstructorAuthMethod(credentialType string) string {
	if constructor, ok := c.CredentialConstructor[credentialType]; ok {
		return constructor.AuthMethod
	}
	return "basic"
}

type CredentialConstructor struct {
	VCT          string                         `yaml:"vct" json:"vct" validate:"required"`
	VCTMFilePath string                         `yaml:"vctm_file_path" json:"vctm_file_path" validate:"required"`
	VCTM         *sdjwt3.VCTM                   `yaml:"-" json:"-"`
	AuthMethod   string                         `yaml:"auth_method" json:"auth_method" validate:"required,oneof=basic pid_auth"`
	Attributes   map[string]map[string][]string `yaml:"attributes" json:"attributes_v2" validate:"omitempty,dive,required"`
}

func (c *CredentialConstructor) LoadFile(ctx context.Context) error {
	if c.VCTMFilePath == "" {
		return fmt.Errorf("vctm_file_path is empty vct: %s", c.VCT)
	}

	fileByte, err := os.ReadFile(c.VCTMFilePath)
	if err != nil {
		return fmt.Errorf("failed to read file %s: %w", c.VCTMFilePath, err)
	}

	if err := json.Unmarshal(fileByte, &c.VCTM); err != nil {
		fmt.Println("Failed to unmarshal VCTM file:", err)
		return err
	}

	c.VCT = c.VCTM.VCT

	return nil
}

// IsAsyncEnabled checks if the async is enabled
func (cfg *Cfg) IsAsyncEnabled(log *logger.Log) bool {
	enabled := cfg.Common.Kafka.Enabled
	if !enabled {
		log.Info("EventPublisher disabled in config")
	}
	return enabled
}

// LoadAndSign loads and signs metadata the issuing metadata from
func (cfg *IssuerMetadata) LoadAndSign(ctx context.Context) (*openid4vci.CredentialIssuerMetadataParameters, any, *x509.Certificate, []string, error) {
	fileByte, err := os.ReadFile(cfg.Path)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	metadata := &openid4vci.CredentialIssuerMetadataParameters{}

	switch filepath.Ext(cfg.Path) {
	case ".json":
		if err := json.Unmarshal(fileByte, &metadata); err != nil {
			return nil, nil, nil, nil, err
		}

	case "yaml", ".yml":
		if err := yaml.Unmarshal(fileByte, &metadata); err != nil {
			return nil, nil, nil, nil, err
		}

	default:
		return nil, nil, nil, nil, errors.New("unsupported file type")
	}

	// ensure that the metadata is empty, should be procured/signed by the request or other automated process
	metadata.SignedMetadata = ""

	privateKey, err := pki.ParseKeyFromFile(cfg.SigningKeyPath)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	cert, chain, err := pki.ParseX509CertificateFromFile(cfg.SigningChainPath)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	chainBase64Encoded := []string{}
	for _, c := range chain {
		chainBase64Encoded = append(chainBase64Encoded, pki.Base64EncodeCertificate(c))
	}

	return metadata, privateKey, cert, chainBase64Encoded, nil
}

// LoadOAuth2Metadata loads OAuth2 metadata from file
func (cfg *OAuthServer) LoadOAuth2Metadata(ctx context.Context) (*oauth2.AuthorizationServerMetadata, any, []string, error) {
	fileByte, err := os.ReadFile(cfg.Metadata.Path)
	if err != nil {
		return nil, nil, nil, err
	}

	metadata := &oauth2.AuthorizationServerMetadata{}

	switch filepath.Ext(cfg.Metadata.Path) {
	case ".json":
		if err := json.Unmarshal(fileByte, &metadata); err != nil {
			return nil, nil, nil, err
		}

	// Not implemented yet
	//case "yaml", ".yml":
	//	if err := yaml.Unmarshal(fileByte, &metadata); err != nil {
	//		return nil, nil, nil, err
	//	}

	default:
		return nil, nil, nil, errors.New("unsupported file type")
	}

	// ensure that the metadata is empty, should be procured/signed by the request or other automated process
	metadata.SignedMetadata = ""

	privateKey, err := pki.ParseKeyFromFile(cfg.Metadata.SigningKeyPath)
	if err != nil {
		return nil, nil, nil, err
	}

	_, chain, err := pki.ParseX509CertificateFromFile(cfg.Metadata.SigningChainPath)
	if err != nil {
		return nil, nil, nil, err
	}

	chainBase64Encoded := []string{}
	for _, c := range chain {
		chainBase64Encoded = append(chainBase64Encoded, pki.Base64EncodeCertificate(c))
	}

	return metadata, privateKey, chainBase64Encoded, nil
}
