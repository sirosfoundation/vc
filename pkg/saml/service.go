package saml

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/xml"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"vc/pkg/logger"
	"vc/pkg/model"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"
)

// Service provides SAML Service Provider functionality
type Service struct {
	cfg          *model.SAMLConfig
	sp           *saml.ServiceProvider
	mdqClient    *MDQClient
	mapper       *AttributeMapper
	sessionStore *SessionStore
	log          *logger.Log
}

// New creates a new SAML service
func New(ctx context.Context, cfg *model.SAMLConfig, log *logger.Log) (*Service, error) {
	if !cfg.Enabled {
		log.Info("SAML support disabled")
		return nil, nil
	}

	s := &Service{
		cfg: cfg,
		log: log.New("saml"),
	}

	// Load X.509 key pair for signing/encryption
	keyPair, err := tls.LoadX509KeyPair(cfg.CertificatePath, cfg.PrivateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load SAML key pair: %w", err)
	}

	keyPair.Leaf, err = x509.ParseCertificate(keyPair.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("failed to parse SAML certificate: %w", err)
	}

	// Parse ACS URL
	acsURL, err := url.Parse(cfg.ACSEndpoint)
	if err != nil {
		return nil, fmt.Errorf("invalid ACS endpoint URL: %w", err)
	}

	// Use metadata URL or fall back to entity ID
	metadataURL := cfg.MetadataURL
	if metadataURL == "" {
		metadataURL = cfg.EntityID
	}
	parsedMetadataURL, err := url.Parse(metadataURL)
	if err != nil {
		return nil, fmt.Errorf("invalid metadata URL: %w", err)
	}

	// Create Service Provider
	s.sp = &saml.ServiceProvider{
		EntityID:          cfg.EntityID,
		Key:               keyPair.PrivateKey.(*rsa.PrivateKey),
		Certificate:       keyPair.Leaf,
		MetadataURL:       *parsedMetadataURL,
		AcsURL:            *acsURL,
		AuthnNameIDFormat: saml.TransientNameIDFormat,
		AllowIDPInitiated: false,
		SignatureMethod:   "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
	}

	// Initialize MDQ client
	s.mdqClient = NewMDQClient(cfg.MDQServer, cfg.MetadataCacheTTL, s.log)

	// Initialize attribute mapper
	s.mapper = NewAttributeMapper(cfg.AttributeMappings, s.log)

	// Initialize session store
	sessionDuration := cfg.SessionDuration
	if sessionDuration == 0 {
		sessionDuration = 3600 // Default 1 hour
	}
	s.sessionStore = NewSessionStore(time.Duration(sessionDuration)*time.Second, s.log)

	s.log.Info("SAML service initialized", "entity_id", cfg.EntityID)

	return s, nil
}

// GetSPMetadata returns the Service Provider metadata XML
func (s *Service) GetSPMetadata(ctx context.Context) (string, error) {
	metadata := s.sp.Metadata()
	xmlBytes, err := xml.MarshalIndent(metadata, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal SP metadata: %w", err)
	}
	return string(xmlBytes), nil
}

// AuthRequest represents a SAML authentication request
type AuthRequest struct {
	ID          string
	RedirectURL string
	RelayState  string
}

// InitiateAuth initiates a SAML authentication flow
func (s *Service) InitiateAuth(ctx context.Context, idpEntityID, credentialType string) (*AuthRequest, error) {
	// Fetch IdP metadata via MDQ
	idpMetadata, err := s.mdqClient.GetIDPMetadata(ctx, idpEntityID)
	if err != nil {
		return nil, fmt.Errorf("failed to get IdP metadata: %w", err)
	}

	// Validate credential type
	if !s.mapper.IsValidCredentialType(credentialType) {
		return nil, fmt.Errorf("unsupported credential type: %s", credentialType)
	}

	// Create authentication request
	req, err := s.sp.MakeAuthenticationRequest(
		idpMetadata.IDPSSODescriptors[0].SingleSignOnServices[0].Location,
		saml.HTTPRedirectBinding,
		saml.HTTPPostBinding,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create authentication request: %w", err)
	}

	// Store session
	session := &SAMLSession{
		ID:             req.ID,
		CredentialType: credentialType,
		IDPEntityID:    idpEntityID,
		CreatedAt:      time.Now(),
	}
	s.sessionStore.Set(req.ID, session)

	// Generate redirect URL
	redirectURL, err := req.Redirect("", s.sp)
	if err != nil {
		return nil, fmt.Errorf("failed to create redirect URL: %w", err)
	}

	return &AuthRequest{
		ID:          req.ID,
		RedirectURL: redirectURL.String(),
		RelayState:  req.ID,
	}, nil
}

// Assertion represents a processed SAML assertion
type Assertion struct {
	NameID     string
	Attributes map[string][]string
	SessionID  string
	NotBefore  time.Time
	NotAfter   time.Time
}

// ProcessAssertion processes a SAML response
func (s *Service) ProcessAssertion(ctx context.Context, samlResponseEncoded string, relayState string) (*Assertion, error) {
	// Retrieve session
	session, err := s.sessionStore.Get(relayState)
	if err != nil {
		return nil, fmt.Errorf("invalid or expired session: %w", err)
	}

	// Fetch IdP metadata
	idpMetadata, err := s.mdqClient.GetIDPMetadata(ctx, session.IDPEntityID)
	if err != nil {
		return nil, fmt.Errorf("failed to get IdP metadata: %w", err)
	}

	// Set IdP metadata on SP for validation
	s.sp.IDPMetadata = idpMetadata

	// Parse and validate SAML response
	samlResp, err := s.sp.ParseResponse(&http.Request{
		PostForm: url.Values{
			"SAMLResponse": {samlResponseEncoded},
			"RelayState":   {session.ID},
		},
	}, []string{session.ID})
	if err != nil {
		return nil, fmt.Errorf("failed to parse SAML response: %w", err)
	}

	// Extract attributes
	attributes := make(map[string][]string)
	for _, attrStatement := range samlResp.AttributeStatements {
		for _, attr := range attrStatement.Attributes {
			values := []string{}
			for _, value := range attr.Values {
				values = append(values, value.Value)
			}
			attributes[attr.Name] = values
		}
	}

	return &Assertion{
		NameID:     samlResp.Subject.NameID.Value,
		Attributes: attributes,
		SessionID:  session.ID,
		NotBefore:  samlResp.Conditions.NotBefore,
		NotAfter:   samlResp.Conditions.NotOnOrAfter,
	}, nil
}

// MapToClaims maps SAML assertion attributes to credential claims
func (s *Service) MapToClaims(ctx context.Context, assertion *Assertion, credentialType string) (map[string]interface{}, error) {
	claims, err := s.mapper.MapAttributes(assertion.Attributes, credentialType)
	if err != nil {
		return nil, fmt.Errorf("failed to map attributes: %w", err)
	}

	// Add subject (NameID) to claims
	claims["sub"] = assertion.NameID

	return claims, nil
}

// GetSession retrieves a session by ID
func (s *Service) GetSession(sessionID string) (*SAMLSession, error) {
	return s.sessionStore.Get(sessionID)
}

// Close cleans up the SAML service
func (s *Service) Close(ctx context.Context) error {
	if s.sessionStore != nil {
		s.sessionStore.Close()
	}
	s.log.Info("SAML service stopped")
	return nil
}

// Middleware returns a Gin middleware for SAML (optional extension point)
func (s *Service) Middleware() samlsp.RequestTracker {
	// Placeholder - could implement custom request tracking if needed
	return nil
}
