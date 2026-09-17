package apiv1

//	@title			Verifier API
//	@version		1.0
//	@description	OIDC and OpenID4VP verifier endpoints.

//	@Summary		OpenID Provider metadata
//	@Description	Returns OpenID Connect discovery metadata for relying parties.
//	@Tags			oidc
//	@Produce		json
//	@Success		200	{object}	DiscoveryMetadata
//	@Router			/.well-known/openid-configuration [get]
func swaggerOIDCDiscovery() {}

//	@Summary		OAuth authorization server metadata
//	@Description	Returns OAuth authorization server metadata.
//	@Tags			oidc
//	@Produce		json
//	@Success		200	{object}	DiscoveryMetadata
//	@Router			/.well-known/oauth-authorization-server [get]
func swaggerOAuthMetadata() {}

//	@Summary		JWKS
//	@Description	Returns the JSON Web Key Set used by verifier tokens.
//	@Tags			oidc
//	@Produce		json
//	@Success		200	{object}	map[string]interface{}
//	@Router			/jwks [get]
func swaggerJWKS() {}

//	@Summary		Authorize
//	@Description	Starts OIDC authorization flow.
//	@Tags			oidc
//	@Produce		html
//	@Param			request	query		AuthorizeRequest	true	"Authorization request"
//	@Success		200		{string}	string			"Authorization page"
//	@Router			/authorize [get]
func swaggerAuthorize() {}

//	@Summary		Token
//	@Description	Exchanges authorization code for tokens.
//	@Tags			oidc
//	@Accept			application/x-www-form-urlencoded
//	@Produce		json
//	@Param			request	formData	TokenRequest	true	"Token request"
//	@Success		200		{object}	TokenResponse
//	@Router			/token [post]
func swaggerToken() {}

//	@Summary		UserInfo
//	@Description	Returns claims for a valid access token.
//	@Tags			oidc
//	@Produce		json
//	@Param			Authorization	header		string	true	"****** token"
//	@Success		200				{object}	UserInfoResponse
//	@Router			/userinfo [get]
func swaggerUserInfo() {}

//	@Summary		Register client
//	@Description	Registers a new OAuth/OIDC client.
//	@Tags			client-registration
//	@Accept			json
//	@Produce		json
//	@Param			request	body		ClientRegistrationRequest	true	"Client registration metadata"
//	@Success		201		{object}	ClientRegistrationResponse
//	@Router			/register [post]
func swaggerRegisterClient() {}

//	@Summary		Get client configuration
//	@Description	Returns registered client metadata.
//	@Tags			client-registration
//	@Produce		json
//	@Param			client_id	path		string	true	"Client ID"
//	@Success		200			{object}	ClientInformationResponse
//	@Router			/register/{client_id} [get]
func swaggerGetClientConfiguration() {}

//	@Summary		Update client configuration
//	@Description	Updates registered client metadata.
//	@Tags			client-registration
//	@Accept			json
//	@Produce		json
//	@Param			client_id	path		string					true	"Client ID"
//	@Param			request		body		UpdateClientRequest		true	"Updated client metadata"
//	@Success		200			{object}	ClientRegistrationResponse
//	@Router			/register/{client_id} [put]
func swaggerUpdateClient() {}

//	@Summary		Delete client configuration
//	@Description	Deletes a registered client.
//	@Tags			client-registration
//	@Param			client_id	path	string	true	"Client ID"
//	@Success		204			"No Content"
//	@Router			/register/{client_id} [delete]
func swaggerDeleteClient() {}

//	@Summary		Get OpenID4VP request object
//	@Description	Returns the signed request object for a verification session.
//	@Tags			openid4vp
//	@Produce		application/oauth-authz-req+jwt
//	@Param			session_id	path		string	true	"Session ID"
//	@Success		200			{string}	string
//	@Router			/verification/request-object/{session_id} [get]
func swaggerOIDCRequestObject() {}

//	@Summary		OpenID4VP direct_post
//	@Description	Receives verifiable presentation from wallet.
//	@Tags			openid4vp
//	@Accept			json
//	@Produce		json
//	@Param			request	body		DirectPostRequest	true	"Wallet response"
//	@Success		200		{object}	DirectPostResponse
//	@Router			/verification/oidc-direct_post [post]
func swaggerOIDCDirectPost() {}

//	@Summary		OpenID4VP callback
//	@Description	Processes callback and redirects back to RP.
//	@Tags			openid4vp
//	@Param			request	query		CallbackRequest	true	"Callback parameters"
//	@Success		302		{string}	string			"Redirect"
//	@Router			/verification/oidc-callback [get]
func swaggerOIDCCallback() {}

//	@Summary		Update session preference
//	@Description	Updates UI/session display preferences.
//	@Tags			session
//	@Accept			json
//	@Produce		json
//	@Param			request	body		UpdateSessionPreferenceRequest	true	"Session preferences"
//	@Success		200		{object}	UpdateSessionPreferenceResponse
//	@Router			/verification/session-preference [post]
func swaggerSessionPreference() {}

//	@Summary		Credential display
//	@Description	Returns credential display page for review.
//	@Tags			session
//	@Produce		html
//	@Param			session_id	path		string	true	"Session ID"
//	@Success		200			{string}	string	"HTML page"
//	@Router			/verification/display/{session_id} [get]
func swaggerCredentialDisplay() {}

//	@Summary		Confirm credential display
//	@Description	Confirms displayed credential and continues flow.
//	@Tags			session
//	@Accept			json
//	@Produce		json
//	@Param			session_id	path		string							true	"Session ID"
//	@Param			request		body		ConfirmCredentialDisplayRequest	true	"Confirmation payload"
//	@Success		200			{object}	ConfirmCredentialDisplayResponse
//	@Router			/verification/confirm/{session_id} [post]
func swaggerConfirmCredentialDisplay() {}

//	@Summary		QR code
//	@Description	Returns QR code image for verification session.
//	@Tags			session
//	@Produce		png
//	@Param			session_id	path		string	true	"Session ID"
//	@Success		200			{string}	string	"PNG image"
//	@Router			/qr/{session_id} [get]
func swaggerQRCode() {}

//	@Summary		Poll session status
//	@Description	Polls the current status of a verification session.
//	@Tags			session
//	@Produce		json
//	@Param			session_id	path		string	true	"Session ID"
//	@Success		200			{object}	PollSessionResponse
//	@Router			/poll/{session_id} [get]
func swaggerPollSession() {}
