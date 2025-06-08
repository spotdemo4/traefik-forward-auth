package server

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/italypaleale/traefik-forward-auth/pkg/auth"
)

// handler for GET /
// Respond with 200, or redirect to oauth
func (s *Server) OAuthRoot(provider auth.OAuth2Provider) func(c *gin.Context) {
	return func(c *gin.Context) {
		// Check if we have a session
		profile := s.getProfileFromContext(c)
		if profile != nil {
			// If we are here, we have a valid session, so respond with a 200 status code
			// Include the user name in the response body in case a visitor is hitting the auth server directly
			s.metrics.RecordAuthentication(true)
			user := s.auth.UserIDFromProfile(profile)
			c.Header("X-Forwarded-User", user)
			c.Header("X-Forwarded-Email", profile.GetEmail())
			c.Data(http.StatusOK, "text/plain; charset=utf-8", []byte(`You're authenticated as '`+user+`'`))
			return
		}

		var err error
		s.metrics.RecordAuthentication(false)

		// Get the return URL
		returnURL := getReturnURL(c)

		// Each state cookie is unique per return URL
		// This avoids issues when there's more than one browser tab that's trying to authenticate, for example because of some background refresh
		stateCookieID := getStateCookieID(returnURL)

		// Check if there's already a state cookie that's recent, so we can re-use the same nonce
		nonce, _, _ := s.getStateCookie(c, stateCookieID)

		if nonce == "" {
			// If there's no nonce, generate a new one
			nonce, err = s.generateNonce()
			if err != nil {
				AbortWithError(c, fmt.Errorf("failed to generate nonce: %w", err))
				return
			}
		}

		// Create a new state and set the cookie
		err = s.setStateCookie(c, nonce, returnURL, stateCookieID)
		if err != nil {
			AbortWithError(c, fmt.Errorf("failed to set state cookie: %w", err))
			return
		}

		// Redirect to the authorization URL
		authURL, err := provider.OAuth2AuthorizeURL(stateCookieID+"~"+nonce, getRedirectURI(c))
		if err != nil {
			AbortWithError(c, fmt.Errorf("failed to get authorize URL: %w", err))
			return
		}

		// Use a custom redirect code to write a response in the body
		c.Header("Location", authURL)
		c.Header("Content-Type", "text/plain; charset=utf-8")
		c.Writer.WriteHeader(http.StatusSeeOther)
		_, _ = c.Writer.WriteString(`Redirecting to authentication server: ` + authURL)
	}
}

// handler for GET /oauth2/callback
// redirect to application
func (s *Server) OAuthCallback(provider auth.OAuth2Provider) func(c *gin.Context) {
	return func(c *gin.Context) {
		// Check if there's an error in the query string
		if qsErr := c.Query("error"); qsErr != "" {
			c.Set("log-message", "Error from the app server: "+qsErr)
			AbortWithError(c, NewResponseError(http.StatusFailedDependency, "The auth server returned an error"))
			return
		}

		// Ensure that we have a state and code parameters
		stateParam := c.Query("state")
		codeParam := c.Query("code")
		if stateParam == "" || codeParam == "" {
			AbortWithError(c, NewResponseError(http.StatusBadRequest, "The parameters 'state' and 'code' are required in the query string"))
			return
		}
		stateCookieID, expectedNonce, ok := strings.Cut(stateParam, "~")
		if !ok {
			AbortWithError(c, NewResponseError(http.StatusUnauthorized, "Query string parameter 'state' is invalid"))
			return
		}

		// Get the state cookie
		nonce, returnURL, err := s.getStateCookie(c, stateCookieID)
		if err != nil {
			AbortWithError(c, fmt.Errorf("invalid state cookie: %w", err))
			return
		} else if nonce == "" {
			AbortWithError(c, NewResponseError(http.StatusUnauthorized, "State cookie not found"))
			return
		}

		// Clear the state cookie
		s.deleteStateCookies(c)

		// Check if the nonce matches
		if nonce != expectedNonce {
			AbortWithError(c, NewResponseError(http.StatusUnauthorized, "Parameters in state cookie do not match state token"))
			return
		}

		// Exchange the code for a token
		at, err := provider.OAuth2ExchangeCode(c.Request.Context(), stateParam, codeParam, getRedirectURI(c))
		if err != nil {
			AbortWithError(c, fmt.Errorf("failed to exchange code for access token: %w", err))
			return
		}

		// Retrieve the user profile
		profile, err := provider.OAuth2RetrieveProfile(c.Request.Context(), at)
		if err != nil {
			AbortWithError(c, fmt.Errorf("failed to retrieve user profile: %w", err))
			return
		}

		// Check if the user is allowed per rules
		err = provider.UserAllowed(profile)
		if err != nil {
			_ = c.Error(fmt.Errorf("access denied per allowlist rules: %w", err))
			AbortWithError(c, NewResponseError(http.StatusUnauthorized, "Access denied per allowlist rules"))
			return
		}

		// Set the profile in the cookie
		err = s.setSessionCookie(c, profile)
		if err != nil {
			AbortWithError(c, fmt.Errorf("failed to set session cookie: %w", err))
			return
		}

		// Use a custom redirect code to write a response in the body
		// We use a 307 redirect here so the client can re-send the request with the original method
		c.Header("Location", returnURL)
		c.Header("Content-Type", "text/plain; charset=utf-8")
		c.Writer.WriteHeader(http.StatusTemporaryRedirect)
		_, _ = c.Writer.WriteString(`Redirecting to application: ` + returnURL)
	}
}
