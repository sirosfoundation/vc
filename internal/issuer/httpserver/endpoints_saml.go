package httpserver

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"go.opentelemetry.io/otel/codes"
)

// endpointSAMLMetadata returns the SAML Service Provider metadata XML
// @Summary Get SAML SP Metadata
// @Description Returns the SAML Service Provider metadata XML for IdP configuration
// @Tags SAML
// @Produce xml
// @Success 200 {string} string "SAML metadata XML"
// @Failure 500 {object} map[string]interface{} "Internal server error"
// @Router /saml/metadata [get]
func (s *Service) endpointSAMLMetadata(ctx context.Context, c *gin.Context) (interface{}, error) {
	ctx, span := s.tracer.Start(ctx, "httpserver:endpointSAMLMetadata")
	defer span.End()

	if s.samlService == nil {
		span.SetStatus(codes.Error, "SAML not configured")
		return nil, fmt.Errorf("SAML is not enabled")
	}

	metadata, err := s.samlService.GetSPMetadata(ctx)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	// Return raw XML with proper content type
	c.Header("Content-Type", "application/samlmetadata+xml")
	c.String(http.StatusOK, metadata)
	return nil, nil
}

// SAMLInitiateRequest represents the request to initiate SAML authentication
type SAMLInitiateRequest struct {
	IDPEntityID    string `json:"idp_entity_id" binding:"required"`
	CredentialType string `json:"credential_type" binding:"required"`
}

// SAMLInitiateResponse represents the response with redirect URL
type SAMLInitiateResponse struct {
	RedirectURL string `json:"redirect_url"`
	RequestID   string `json:"request_id"`
}

// endpointSAMLInitiate initiates SAML authentication flow
// @Summary Initiate SAML Authentication
// @Description Initiates SAML authentication by creating an AuthnRequest and returning the IdP redirect URL
// @Tags SAML
// @Accept json
// @Produce json
// @Param request body SAMLInitiateRequest true "SAML initiate request"
// @Success 200 {object} SAMLInitiateResponse
// @Failure 400 {object} map[string]interface{} "Bad request"
// @Failure 500 {object} map[string]interface{} "Internal server error"
// @Router /saml/initiate [post]
func (s *Service) endpointSAMLInitiate(ctx context.Context, c *gin.Context) (interface{}, error) {
	ctx, span := s.tracer.Start(ctx, "httpserver:endpointSAMLInitiate")
	defer span.End()

	if s.samlService == nil {
		span.SetStatus(codes.Error, "SAML not configured")
		return nil, fmt.Errorf("SAML is not enabled")
	}

	var req SAMLInitiateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	authReq, err := s.samlService.InitiateAuth(ctx, req.IDPEntityID, req.CredentialType)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	return &SAMLInitiateResponse{
		RedirectURL: authReq.RedirectURL,
		RequestID:   authReq.ID,
	}, nil
}

// endpointSAMLACS handles the SAML Assertion Consumer Service (ACS) endpoint
// This is where the IdP POSTs the SAML response after authentication
// @Summary SAML Assertion Consumer Service
// @Description Receives and processes SAML assertions from the IdP
// @Tags SAML
// @Accept application/x-www-form-urlencoded
// @Produce json
// @Param SAMLResponse formData string true "Base64-encoded SAML Response"
// @Param RelayState formData string false "Relay state from initial request"
// @Success 200 {object} map[string]interface{} "Success with credential claims or offer"
// @Failure 400 {object} map[string]interface{} "Bad request"
// @Failure 500 {object} map[string]interface{} "Internal server error"
// @Router /saml/acs [post]
func (s *Service) endpointSAMLACS(ctx context.Context, c *gin.Context) (interface{}, error) {
	ctx, span := s.tracer.Start(ctx, "httpserver:endpointSAMLACS")
	defer span.End()

	if s.samlService == nil {
		span.SetStatus(codes.Error, "SAML not configured")
		return nil, fmt.Errorf("SAML is not enabled")
	}

	// Extract SAML response from POST form data
	samlResponseB64 := c.PostForm("SAMLResponse")
	if samlResponseB64 == "" {
		span.SetStatus(codes.Error, "missing SAMLResponse")
		return nil, fmt.Errorf("SAMLResponse parameter is required")
	}

	// Decode base64
	samlResponseXML, err := base64.StdEncoding.DecodeString(samlResponseB64)
	if err != nil {
		span.SetStatus(codes.Error, "invalid base64")
		return nil, fmt.Errorf("failed to decode SAMLResponse: %w", err)
	}

	relayState := c.PostForm("RelayState")

	// Process the SAML assertion
	assertion, err := s.samlService.ProcessAssertion(ctx, string(samlResponseXML), relayState)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	// Retrieve session to get credential type
	session, err := s.samlService.GetSession(relayState)
	if err != nil {
		span.SetStatus(codes.Error, "session retrieval failed")
		return nil, fmt.Errorf("failed to retrieve session: %w", err)
	}

	// Map SAML attributes to credential claims
	claims, err := s.samlService.MapToClaims(ctx, assertion, session.CredentialType)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	s.log.Info("SAML authentication successful",
		"credential_type", session.CredentialType,
		"claims_count", len(claims))

	// TODO: Phase 3 - Bridge to credential issuance
	// For now, return the extracted claims
	// In the next phase, we'll:
	// 1. Route to appropriate credential type handler
	// 2. Generate credential using claims
	// 3. Create credential offer for wallet
	// 4. Return offer URL or redirect user

	response := map[string]interface{}{
		"status":          "authenticated",
		"credential_type": session.CredentialType,
		"claims":          claims,
		"message":         "SAML authentication successful. Credential issuance integration pending.",
	}

	return response, nil
}
