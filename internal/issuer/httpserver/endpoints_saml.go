//go:build saml

package httpserver

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"time"

	apiv1_issuer "vc/internal/gen/issuer/apiv1_issuer"
	"vc/internal/issuer/apiv1"
	"vc/pkg/education"
	"vc/pkg/model"
	"vc/pkg/openid4vci"
	"vc/pkg/pid"
	"vc/pkg/socialsecurity"

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

	// Convert SAML claims to document structure based on credential type
	documentData, err := s.claimsToDocument(ctx, claims, session.CredentialType)
	if err != nil {
		span.SetStatus(codes.Error, "document conversion failed")
		return nil, fmt.Errorf("failed to convert claims to document: %w", err)
	}

	// Generate ephemeral JWK for credential binding if not provided
	// In a production scenario, the wallet would provide the JWK
	jwk := session.JWK
	if jwk == nil {
		// For SAML flow without wallet involvement, we generate a JWK
		// This is primarily for testing and backward compatibility
		s.log.Info("No JWK provided in session, generating ephemeral key")
		// TODO: Consider if we should require JWK from wallet instead
	}

	// Create credential using the issuer API
	credential, err := s.createCredential(ctx, session.CredentialType, documentData, jwk)
	if err != nil {
		span.SetStatus(codes.Error, "credential creation failed")
		return nil, fmt.Errorf("failed to create credential: %w", err)
	}

	// Generate credential offer for wallet
	credentialOffer, err := s.generateCredentialOffer(ctx, session.CredentialType, session.CredentialConfigID)
	if err != nil {
		span.SetStatus(codes.Error, "credential offer generation failed")
		return nil, fmt.Errorf("failed to generate credential offer: %w", err)
	}

	s.log.Info("Credential issued successfully",
		"credential_type", session.CredentialType,
		"offer_id", credentialOffer["id"])

	response := map[string]interface{}{
		"status":           "success",
		"credential_type":  session.CredentialType,
		"credential":       credential,
		"credential_offer": credentialOffer,
		"message":          "SAML authentication and credential issuance successful",
	}

	return response, nil
}

// claimsToDocument converts SAML claims to a credential-specific document structure
func (s *Service) claimsToDocument(ctx context.Context, claims map[string]interface{}, credentialType string) ([]byte, error) {
	ctx, span := s.tracer.Start(ctx, "httpserver:claimsToDocument")
	defer span.End()

	var doc interface{}
	var err error

	switch credentialType {
	case "urn:eudi:pid:1":
		doc, err = s.claimsToPIDDocument(claims)
	case "urn:eudi:diploma:1":
		doc, err = s.claimsToDiplomaDocument(claims)
	case "urn:eudi:ehic:1":
		doc, err = s.claimsToEHICDocument(claims)
	default:
		return nil, fmt.Errorf("unsupported credential type: %s", credentialType)
	}

	if err != nil {
		return nil, err
	}

	// Marshal to JSON
	data, err := json.Marshal(doc)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal document: %w", err)
	}

	return data, nil
}

// claimsToPIDDocument converts claims to a PID document
func (s *Service) claimsToPIDDocument(claims map[string]interface{}) (*pid.Document, error) {
	identity := &model.Identity{
		Schema: &model.IdentitySchema{
			Name:    "https://github.com/dc4eu/vc/identity/1.0",
			Version: "1.0.0",
		},
	}

	// Map required fields
	if v, ok := claims["family_name"].(string); ok && v != "" {
		identity.FamilyName = v
	} else {
		return nil, fmt.Errorf("missing required field: family_name")
	}

	if v, ok := claims["given_name"].(string); ok && v != "" {
		identity.GivenName = v
	} else {
		return nil, fmt.Errorf("missing required field: given_name")
	}

	if v, ok := claims["birth_date"].(string); ok && v != "" {
		identity.BirthDate = v
	} else {
		return nil, fmt.Errorf("missing required field: birth_date")
	}

	// Map optional fields
	if v, ok := claims["birth_place"].(string); ok {
		identity.BirthPlace = v
	}

	if v, ok := claims["nationality"]; ok {
		if arr, ok := v.([]string); ok {
			identity.Nationality = arr
		} else if str, ok := v.(string); ok {
			identity.Nationality = []string{str}
		}
	}

	if v, ok := claims["personal_administrative_number"].(string); ok {
		identity.PersonalAdministrativeNumber = v
	}

	if v, ok := claims["sex"].(string); ok {
		identity.Sex = v
	}

	if v, ok := claims["email_address"].(string); ok {
		identity.EmailAddress = v
	}

	if v, ok := claims["mobile_phone_number"].(string); ok {
		identity.MobilePhoneNumber = v
	}

	// Map address fields
	if v, ok := claims["resident_street_address"].(string); ok {
		identity.ResidentStreetAddress = v
	}

	if v, ok := claims["resident_house_number"].(string); ok {
		identity.ResidentHouseNumber = v
	}

	if v, ok := claims["resident_postal_code"].(string); ok {
		identity.ResidentPostalCode = v
	}

	if v, ok := claims["resident_city"].(string); ok {
		identity.ResidentCity = v
	}

	if v, ok := claims["resident_state"].(string); ok {
		identity.ResidentState = v
	}

	if v, ok := claims["resident_country"].(string); ok {
		identity.ResidentCountry = v
	}

	return &pid.Document{Identity: identity}, nil
}

// claimsToDiplomaDocument converts claims to a Diploma document
func (s *Service) claimsToDiplomaDocument(claims map[string]interface{}) (*education.DiplomaDocument, error) {
	// Create a new diploma with defaults
	doc := education.NewDiploma()

	// Update with SAML claims if available
	if dateOfBirth, ok := claims["birth_date"].(string); ok && dateOfBirth != "" {
		// Convert to required format if needed
		doc.CredentialSubject.DateOfBirth = dateOfBirth
	}

	// Additional diploma-specific claim mappings can be added here
	// For example: degree title, awarding institution, graduation date, etc.

	return doc, nil
}

// claimsToEHICDocument converts claims to an EHIC document
func (s *Service) claimsToEHICDocument(claims map[string]interface{}) (*socialsecurity.EHICDocument, error) {
	// EHIC requires health insurance information
	// This is a simplified implementation - SAML may not provide all required EHIC fields
	// A production implementation would need additional data sources or configuration
	
	doc := &socialsecurity.EHICDocument{
		// Map required EHIC fields from SAML claims where available
		// Note: Many EHIC fields may not be available from SAML and would need
		// to come from a health insurance authority
	}

	// Map personal administrative number (e.g., SSN)
	if pan, ok := claims["personal_administrative_number"].(string); ok && pan != "" {
		doc.PersonalAdministrativeNumber = pan
	} else {
		return nil, fmt.Errorf("missing required field for EHIC: personal_administrative_number")
	}

	// Additional required EHIC fields that may not be available from SAML
	// These would typically need to come from a health insurance database
	// For now, return an error indicating EHIC issuance requires more data
	return nil, fmt.Errorf("EHIC credential issuance requires health insurance data not available from SAML")
}

// createCredential calls the issuer API to create a credential
func (s *Service) createCredential(ctx context.Context, credentialType string, documentData []byte, jwk *apiv1_issuer.Jwk) (string, error) {
	ctx, span := s.tracer.Start(ctx, "httpserver:createCredential")
	defer span.End()

	// Create credential request
	req := &apiv1.CreateCredentialRequest{
		DocumentType: credentialType,
		DocumentData: documentData,
		JWK:          jwk,
	}

	// Call the credential creation API
	reply, err := s.apiv1.MakeSDJWT(ctx, req)
	if err != nil {
		return "", fmt.Errorf("failed to create credential: %w", err)
	}

	if reply == nil || len(reply.Data) == 0 {
		return "", fmt.Errorf("no credential data returned")
	}

	// Return the first credential (assuming single credential response)
	return reply.Data[0].Credential, nil
}

// generateCredentialOffer creates an OpenID4VCI credential offer
func (s *Service) generateCredentialOffer(ctx context.Context, credentialType string, credentialConfigID string) (map[string]interface{}, error) {
	ctx, span := s.tracer.Start(ctx, "httpserver:generateCredentialOffer")
	defer span.End()

	// Build credential offer parameters
	params := openid4vci.CredentialOfferParameters{
		CredentialIssuer:           s.cfg.Common.CredentialOffer.IssuerURL,
		CredentialConfigurationIDs: []string{credentialConfigID},
		Grants: map[string]interface{}{
			"urn:ietf:params:oauth:grant-type:pre-authorized_code": map[string]interface{}{
				"pre-authorized_code": generatePreAuthCode(),
				"tx_code":             nil, // Optional transaction code
			},
		},
	}

	// Generate credential offer
	offer, err := params.CredentialOffer()
	if err != nil {
		return nil, fmt.Errorf("failed to generate credential offer: %w", err)
	}

	// Convert to map for response
	offerData := make(map[string]interface{})
	offerJSON, err := json.Marshal(offer)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal credential offer: %w", err)
	}

	if err := json.Unmarshal(offerJSON, &offerData); err != nil {
		return nil, fmt.Errorf("failed to unmarshal credential offer: %w", err)
	}

	return offerData, nil
}

// generatePreAuthCode generates a pre-authorized code for the credential offer
// In production, this should be cryptographically secure and stored in the database
func generatePreAuthCode() string {
	// TODO: Replace with secure random generation and database storage
	// For now, use a simple UUID-like string
	return fmt.Sprintf("%d-%d", time.Now().Unix(), rand.Int63())
}
