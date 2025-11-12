/*
 * Teleport
 * Copyright (C) 2024  Gravitational, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"net/url"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gravitational/trace"
	"golang.org/x/oauth2"

	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/auth/authclient"
	"github.com/gravitational/teleport/lib/services"
)

// ErrOIDCNoRoles results from an OIDC user not having any roles mapped.
var ErrOIDCNoRoles = trace.AccessDenied("user does not have any roles mapped; check the claims_to_roles configuration in the OIDC connector")

// oidcAuthServiceImpl implements OIDCService interface
type oidcAuthServiceImpl struct {
	authServer *Server
}

// NewOIDCAuthService creates a new OIDC authentication service
func NewOIDCAuthService(authServer *Server) OIDCService {
	return &oidcAuthServiceImpl{
		authServer: authServer,
	}
}

// CreateOIDCAuthRequest creates an OIDC authentication request
func (s *oidcAuthServiceImpl) CreateOIDCAuthRequest(ctx context.Context, req types.OIDCAuthRequest) (*types.OIDCAuthRequest, error) {
	return s.createOIDCAuthRequest(ctx, req, false)
}

// CreateOIDCAuthRequestForMFA creates an OIDC authentication request for MFA
func (s *oidcAuthServiceImpl) CreateOIDCAuthRequestForMFA(ctx context.Context, req types.OIDCAuthRequest) (*types.OIDCAuthRequest, error) {
	return s.createOIDCAuthRequest(ctx, req, true)
}

// createOIDCAuthRequest is the common implementation for creating OIDC auth requests
func (s *oidcAuthServiceImpl) createOIDCAuthRequest(ctx context.Context, req types.OIDCAuthRequest, forMFA bool) (*types.OIDCAuthRequest, error) {
	// Get the OIDC connector
	connector, err := s.authServer.GetOIDCConnector(ctx, req.ConnectorID, true)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// Generate state token for CSRF protection
	stateToken, err := generateRandomToken(32)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// Determine redirect URL
	redirectURL, err := services.GetRedirectURL(connector, req.ProxyAddress)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// Create OAuth2 config
	oauth2Config := oauth2.Config{
		ClientID:     connector.GetClientID(),
		ClientSecret: connector.GetClientSecret(),
		RedirectURL:  redirectURL,
		Endpoint: oauth2.Endpoint{
			AuthURL:  connector.GetIssuerURL() + "/protocol/openid-connect/auth",
			TokenURL: connector.GetIssuerURL() + "/protocol/openid-connect/token",
		},
		Scopes: connector.GetScope(),
	}

	// Build auth code URL options
	var authURLOpts []oauth2.AuthCodeOption

	// Add PKCE if verifier is provided
	if req.PkceVerifier != "" {
		authURLOpts = append(authURLOpts, oauth2.S256ChallengeOption(req.PkceVerifier))
	}

	// Generate authorization URL
	authURL := oauth2Config.AuthCodeURL(stateToken, authURLOpts...)

	// Store the auth request state
	authRequest := types.OIDCAuthRequest{
		ConnectorID:       req.ConnectorID,
		Type:              req.Type,
		CheckUser:         req.CheckUser,
		StateToken:        stateToken,
		CSRFToken:         req.CSRFToken,
		RedirectURL:       authURL,
		ClientRedirectURL: req.ClientRedirectURL,
		CertTTL:           req.CertTTL,
		CreateWebSession:  req.CreateWebSession,
		ProxyAddress:      req.ProxyAddress,
		PkceVerifier:      req.PkceVerifier,
		SshPublicKey:      req.SshPublicKey,
		TlsPublicKey:      req.TlsPublicKey,
	}

	// Store the request in cache/storage for later validation
	if err := s.storeOIDCAuthRequest(ctx, stateToken, &authRequest); err != nil {
		return nil, trace.Wrap(err)
	}

	return &authRequest, nil
}

// ValidateOIDCAuthCallback validates the OIDC callback and creates a user session
func (s *oidcAuthServiceImpl) ValidateOIDCAuthCallback(ctx context.Context, q url.Values) (*authclient.OIDCAuthResponse, error) {
	// Extract parameters from callback
	code := q.Get("code")
	if code == "" {
		return nil, trace.BadParameter("missing code parameter")
	}

	state := q.Get("state")
	if state == "" {
		return nil, trace.BadParameter("missing state parameter")
	}

	// Retrieve stored auth request
	authRequest, err := s.getOIDCAuthRequest(ctx, state)
	if err != nil {
		s.authServer.logger.ErrorContext(ctx, "Failed to retrieve stored auth request", "error", err, "state", state)
		return nil, trace.Wrap(err)
	}

	s.authServer.logger.InfoContext(ctx, "Retrieved auth request",
		"connector_id", authRequest.ConnectorID,
		"proxy_address", authRequest.ProxyAddress,
		"create_web_session", authRequest.CreateWebSession,
		"ssh_pub_key_len", len(authRequest.SshPublicKey),
		"tls_pub_key_len", len(authRequest.TlsPublicKey))

	// Get the OIDC connector
	connector, err := s.authServer.GetOIDCConnector(ctx, authRequest.ConnectorID, true)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// Determine redirect URL
	redirectURL, err := services.GetRedirectURL(connector, authRequest.ProxyAddress)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	s.authServer.logger.InfoContext(ctx, "Validating OIDC callback",
		"code_length", len(code),
		"state_length", len(state),
		"redirect_url", redirectURL,
		"proxy_address", authRequest.ProxyAddress)

	// Create OAuth2 config with explicit endpoint configuration
	oauth2Config := oauth2.Config{
		ClientID:     connector.GetClientID(),
		ClientSecret: connector.GetClientSecret(),
		RedirectURL:  redirectURL,
		Endpoint: oauth2.Endpoint{
			AuthURL:   connector.GetIssuerURL() + "/protocol/openid-connect/auth",
			TokenURL:  connector.GetIssuerURL() + "/protocol/openid-connect/token",
			AuthStyle: oauth2.AuthStyleInHeader, // Use HTTP Basic authentication (standard for Keycloak)
		},
		Scopes: connector.GetScope(),
	}

	// Debug logging
	s.authServer.logger.InfoContext(ctx, "OIDC token exchange",
		"client_id", connector.GetClientID(),
		"client_secret_length", len(connector.GetClientSecret()),
		"client_secret_first_4", connector.GetClientSecret()[:min(4, len(connector.GetClientSecret()))],
		"redirect_url", redirectURL,
		"token_url", oauth2Config.Endpoint.TokenURL,
		"issuer_url", connector.GetIssuerURL())

	// Exchange code for token
	var tokenOpts []oauth2.AuthCodeOption
	if authRequest.PkceVerifier != "" {
		tokenOpts = append(tokenOpts, oauth2.VerifierOption(authRequest.PkceVerifier))
	}

	token, err := oauth2Config.Exchange(ctx, code, tokenOpts...)
	if err != nil {
		s.authServer.logger.ErrorContext(ctx, "Token exchange failed",
			"error", err,
			"client_id", connector.GetClientID(),
			"redirect_url", redirectURL)
		return nil, trace.Wrap(err, "failed to exchange code for token")
	}

	// Extract ID token
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		return nil, trace.BadParameter("no id_token in token response")
	}

	// Create OIDC provider and verify token
	provider, err := oidc.NewProvider(ctx, connector.GetIssuerURL())
	if err != nil {
		return nil, trace.Wrap(err, "failed to create OIDC provider")
	}

	verifier := provider.Verifier(&oidc.Config{
		ClientID: connector.GetClientID(),
	})

	idToken, err := verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, trace.Wrap(err, "failed to verify ID token")
	}

	// Extract claims
	var claims struct {
		Email             string   `json:"email"`
		PreferredUsername string   `json:"preferred_username"`
		Name              string   `json:"name"`
		Groups            []string `json:"groups"`
	}

	if err := idToken.Claims(&claims); err != nil {
		return nil, trace.Wrap(err, "failed to extract claims")
	}

	// Determine username
	username := claims.Email
	usernameClaim := connector.GetUsernameClaim()
	if usernameClaim == "" {
		usernameClaim = "email"
	}
	if usernameClaim == "preferred_username" && claims.PreferredUsername != "" {
		username = claims.PreferredUsername
	}

	// Map claims to roles
	roles := mapClaimsToRoles(connector, claims.Email, claims.Groups)
	if len(roles) == 0 {
		return nil, trace.Wrap(ErrOIDCNoRoles, "no roles mapped for user %s", username)
	}

	// Create or update user
	user, err := s.createOrUpdateOIDCUser(ctx, username, connector.GetName(), roles, claims.Email)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// Create response
	response := &authclient.OIDCAuthResponse{
		Username: user.GetName(),
		Identity: types.ExternalIdentity{
			ConnectorID: connector.GetName(),
			Username:    username,
		},
		Req: authclient.OIDCAuthRequest{
			ConnectorID:       authRequest.ConnectorID,
			CSRFToken:         authRequest.CSRFToken,
			CreateWebSession:  authRequest.CreateWebSession,
			ClientRedirectURL: authRequest.ClientRedirectURL,
			SSHPubKey:         authRequest.SshPublicKey,
			TLSPubKey:         authRequest.TlsPublicKey,
		},
	}

	// Get user state for certificate generation
	userState, err := s.authServer.GetUserOrLoginState(ctx, user.GetName())
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// Create web session if requested
	if authRequest.CreateWebSession {
		sess, err := s.authServer.CreateWebSessionFromReq(ctx, NewWebSessionRequest{
			User:       user.GetName(),
			Roles:      roles,
			Traits:     user.GetTraits(),
			SessionTTL: authRequest.CertTTL,
		})
		if err != nil {
			return nil, trace.Wrap(err)
		}
		response.Session = sess
	}

	// If a public key was provided, sign it and return a certificate (for CLI login)
	if len(authRequest.SshPublicKey) != 0 || len(authRequest.TlsPublicKey) != 0 {
		s.authServer.logger.InfoContext(ctx, "Generating certificates for console login",
			"ssh_pub_key_len", len(authRequest.SshPublicKey),
			"tls_pub_key_len", len(authRequest.TlsPublicKey),
			"username", user.GetName())

		sshCert, tlsCert, err := s.authServer.CreateSessionCerts(ctx, &SessionCertsRequest{
			UserState:  userState,
			SessionTTL: authRequest.CertTTL,
			SSHPubKey:  authRequest.SshPublicKey,
			TLSPubKey:  authRequest.TlsPublicKey,
		})
		if err != nil {
			return nil, trace.Wrap(err, "failed to create session certificates")
		}

		clusterName, err := s.authServer.GetClusterName(ctx)
		if err != nil {
			return nil, trace.Wrap(err, "failed to obtain cluster name")
		}

		response.Cert = sshCert
		response.TLSCert = tlsCert

		s.authServer.logger.InfoContext(ctx, "Generated certificates",
			"ssh_cert_len", len(sshCert),
			"tls_cert_len", len(tlsCert))

		// Return the host CA for this cluster only
		authority, err := s.authServer.GetCertAuthority(ctx, types.CertAuthID{
			Type:       types.HostCA,
			DomainName: clusterName.GetClusterName(),
		}, false)
		if err != nil {
			return nil, trace.Wrap(err, "failed to obtain cluster's host CA")
		}
		response.HostSigners = append(response.HostSigners, authority)
	} else {
		s.authServer.logger.InfoContext(ctx, "Skipping certificate generation - no public keys provided")
	}

	// Clean up stored auth request
	if err := s.deleteOIDCAuthRequest(ctx, state); err != nil {
		s.authServer.logger.WarnContext(ctx, "Failed to delete OIDC auth request", "error", err)
	}

	return response, nil
}

// mapClaimsToRoles maps OIDC claims to Teleport roles
func mapClaimsToRoles(connector types.OIDCConnector, email string, groups []string) []string {
	var roles []string
	rolesMap := make(map[string]bool)

	for _, mapping := range connector.GetClaimsToRoles() {
		var matched bool

		switch mapping.Claim {
		case "email":
			matched = matchPattern(mapping.Value, email)
		case "groups":
			for _, group := range groups {
				if matchPattern(mapping.Value, group) {
					matched = true
					break
				}
			}
		}

		if matched {
			for _, role := range mapping.Roles {
				if !rolesMap[role] {
					rolesMap[role] = true
					roles = append(roles, role)
				}
			}
		}
	}

	return roles
}

// matchPattern matches a value against a pattern (supports wildcards)
func matchPattern(pattern, value string) bool {
	if pattern == "*" {
		return true
	}
	if len(pattern) > 0 && pattern[0] == '*' {
		suffix := pattern[1:]
		return len(value) >= len(suffix) && value[len(value)-len(suffix):] == suffix
	}
	return pattern == value
}

// createOrUpdateOIDCUser creates or updates a user based on OIDC authentication
func (s *oidcAuthServiceImpl) createOrUpdateOIDCUser(ctx context.Context, username, connectorName string, roles []string, email string) (types.User, error) {
	// Try to get existing user
	user, err := s.authServer.GetUser(ctx, username, false)
	if err != nil && !trace.IsNotFound(err) {
		return nil, trace.Wrap(err)
	}

	if trace.IsNotFound(err) {
		// Create new user
		user, err = types.NewUser(username)
		if err != nil {
			return nil, trace.Wrap(err)
		}
	}

	// Update user roles and identity
	user.SetRoles(roles)

	// Add or update OIDC identity
	identities := user.GetOIDCIdentities()
	found := false
	for i, id := range identities {
		if id.ConnectorID == connectorName {
			identities[i].Username = username
			found = true
			break
		}
	}
	if !found {
		identities = append(identities, types.ExternalIdentity{
			ConnectorID: connectorName,
			Username:    username,
		})
	}

	// Since we can't directly set OIDCIdentities, we need to work with the user's spec
	// This is a workaround - in a real implementation, the user type should have a setter method
	if userV2, ok := user.(*types.UserV2); ok {
		userV2.Spec.OIDCIdentities = identities
	}

	// Upsert user
	if _, err := s.authServer.UpsertUser(ctx, user); err != nil {
		return nil, trace.Wrap(err)
	}

	return user, nil
}

// Storage helpers for auth requests (using a simple in-memory cache for now)
var oidcAuthRequestCache = make(map[string]*types.OIDCAuthRequest)

func (s *oidcAuthServiceImpl) storeOIDCAuthRequest(ctx context.Context, stateToken string, req *types.OIDCAuthRequest) error {
	oidcAuthRequestCache[stateToken] = req
	// In production, this should use the backend storage with TTL
	return nil
}

func (s *oidcAuthServiceImpl) getOIDCAuthRequest(ctx context.Context, stateToken string) (*types.OIDCAuthRequest, error) {
	req, ok := oidcAuthRequestCache[stateToken]
	if !ok {
		return nil, trace.NotFound("OIDC auth request not found")
	}
	return req, nil
}

func (s *oidcAuthServiceImpl) deleteOIDCAuthRequest(ctx context.Context, stateToken string) error {
	delete(oidcAuthRequestCache, stateToken)
	return nil
}

// generateRandomToken generates a random token for CSRF protection
func generateRandomToken(length int) (string, error) {
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return "", trace.Wrap(err)
	}
	return base64.URLEncoding.EncodeToString(b), nil
}
