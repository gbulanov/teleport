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

package web

import (
	"errors"
	"net/http"
	"strings"

	"github.com/gravitational/trace"
	"github.com/julienschmidt/httprouter"

	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/auth"
	"github.com/gravitational/teleport/lib/client"
	"github.com/gravitational/teleport/lib/httplib"
)

// oidcLoginWeb handles OIDC login requests from the web UI
func (h *Handler) oidcLoginWeb(w http.ResponseWriter, r *http.Request, p httprouter.Params) string {
	logger := h.logger.With("auth", "oidc")
	logger.DebugContext(r.Context(), "Web login start")

	req, err := ParseSSORequestParams(r)
	if err != nil {
		logger.ErrorContext(r.Context(), "Failed to extract SSO parameters from request", "error", err)
		return client.LoginFailedRedirectURL
	}

	response, err := h.cfg.ProxyClient.CreateOIDCAuthRequest(r.Context(), types.OIDCAuthRequest{
		CSRFToken:         req.CSRFToken,
		ConnectorID:       req.ConnectorID,
		CreateWebSession:  true,
		ClientRedirectURL: req.ClientRedirectURL,
		ProxyAddress:      h.cfg.ProxyPublicAddrs[0].String(),
	})
	if err != nil {
		logger.ErrorContext(r.Context(), "Error creating auth request", "error", err)
		return client.LoginFailedRedirectURL
	}

	return response.RedirectURL
}

// oidcLoginConsole handles OIDC login requests from the console/CLI
func (h *Handler) oidcLoginConsole(w http.ResponseWriter, r *http.Request, p httprouter.Params) (any, error) {
	logger := h.logger.With("auth", "oidc")
	logger.DebugContext(r.Context(), "Console login start")

	req := new(client.SSOLoginConsoleReq)
	if err := httplib.ReadResourceJSON(r, req); err != nil {
		logger.ErrorContext(r.Context(), "Error reading json", "error", err)
		return nil, trace.AccessDenied("%s", SSOLoginFailureMessage)
	}

	if err := req.CheckAndSetDefaults(); err != nil {
		logger.ErrorContext(r.Context(), "Missing request parameters", "error", err)
		return nil, trace.AccessDenied("%s", SSOLoginFailureMessage)
	}

	logger.DebugContext(r.Context(), "Creating OIDC auth request",
		"connector_id", req.ConnectorID,
		"ssh_pub_key_len", len(req.SSHPubKey),
		"tls_pub_key_len", len(req.TLSPubKey),
		"cert_ttl", req.CertTTL)

	response, err := h.cfg.ProxyClient.CreateOIDCAuthRequest(r.Context(), types.OIDCAuthRequest{
		ConnectorID:       req.ConnectorID,
		ClientRedirectURL: req.RedirectURL,
		CertTTL:           req.CertTTL,
		ProxyAddress:      h.cfg.ProxyPublicAddrs[0].String(),
		PkceVerifier:      req.PKCEVerifier,
		SshPublicKey:      req.SSHPubKey,
		TlsPublicKey:      req.TLSPubKey,
	})
	if err != nil {
		logger.ErrorContext(r.Context(), "Failed to create OIDC auth request", "error", err)
		if strings.Contains(err.Error(), auth.InvalidClientRedirectErrorMessage) {
			return nil, trace.AccessDenied("%s", SSOLoginFailureInvalidRedirect)
		}
		return nil, trace.AccessDenied("%s", SSOLoginFailureMessage)
	}

	return &client.SSOLoginConsoleResponse{
		RedirectURL: response.RedirectURL,
	}, nil
}

// oidcCallback handles the OIDC provider callback
func (h *Handler) oidcCallback(w http.ResponseWriter, r *http.Request, p httprouter.Params) string {
	logger := h.logger.With("auth", "oidc")
	logger.DebugContext(r.Context(), "Callback start", "query", r.URL.Query())

	response, err := h.cfg.ProxyClient.ValidateOIDCAuthCallback(r.Context(), r.URL.Query())
	if err != nil {
		logger.ErrorContext(r.Context(), "Error while processing callback", "error", err)

		// try to find the auth request, which bears the original client redirect URL.
		// if found, use it to terminate the flow.
		//
		// this improves the UX by terminating the failed SSO flow immediately, rather than hoping for a timeout.
		if requestID := r.URL.Query().Get("state"); requestID != "" {
			if request, errGet := h.cfg.ProxyClient.GetOIDCAuthRequest(r.Context(), requestID); errGet == nil && !request.CreateWebSession {
				if redURL, errEnc := RedirectURLWithError(request.ClientRedirectURL, err); errEnc == nil {
					return redURL.String()
				}
			}
		}
		if errors.Is(err, auth.ErrOIDCNoRoles) {
			return client.LoginFailedUnauthorizedRedirectURL
		}

		return client.LoginFailedBadCallbackRedirectURL
	}

	// if we created web session, set session cookie and redirect to original url
	if response.Req.CreateWebSession {
		logger.InfoContext(r.Context(), "Redirecting to web browser")

		res := &SSOCallbackResponse{
			CSRFToken:         response.Req.CSRFToken,
			Username:          response.Username,
			SessionName:       response.Session.GetName(),
			SessionExpiry:     response.Session.Expiry(),
			ClientRedirectURL: response.Req.ClientRedirectURL,
		}

		if err := SSOSetWebSessionAndRedirectURL(w, r, res, true); err != nil {
			logger.ErrorContext(r.Context(), "Error setting web session.", "error", err)
			return client.LoginFailedRedirectURL
		}

		if dwt := response.Session.GetDeviceWebToken(); dwt != nil {
			logger.DebugContext(r.Context(), "OIDC WebSession created with device web token")
			// if a device web token is present, we must send the user to the device authorize page
			// to upgrade the session.
			redirectPath, err := BuildDeviceWebRedirectPath(dwt, res.ClientRedirectURL)
			if err != nil {
				logger.DebugContext(r.Context(), "Invalid device web token", "error", err)
			}
			return redirectPath
		}
		return res.ClientRedirectURL
	}

	logger.InfoContext(r.Context(), "Callback is redirecting to console login",
		"ssh_pub_key_len", len(response.Req.SSHPubKey),
		"tls_pub_key_len", len(response.Req.TLSPubKey))

	if len(response.Req.SSHPubKey)+len(response.Req.TLSPubKey) == 0 {
		logger.ErrorContext(r.Context(), "Not a web or console login request - missing public keys",
			"ssh_pub_key_len", len(response.Req.SSHPubKey),
			"tls_pub_key_len", len(response.Req.TLSPubKey))
		return client.LoginFailedRedirectURL
	}

	redirectURL, err := ConstructSSHResponse(AuthParams{
		ClientRedirectURL: response.Req.ClientRedirectURL,
		Username:          response.Username,
		Identity:          response.Identity,
		Session:           response.Session,
		Cert:              response.Cert,
		TLSCert:           response.TLSCert,
		HostSigners:       response.HostSigners,
		FIPS:              h.cfg.FIPS,
	})
	if err != nil {
		logger.ErrorContext(r.Context(), "Error constructing ssh response", "error", err)
		return client.LoginFailedRedirectURL
	}

	return redirectURL.String()
}
