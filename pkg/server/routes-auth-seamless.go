package server

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/italypaleale/traefik-forward-auth/pkg/auth"
)

// handler for GET /
// Return 200 if valid
func (s *Server) SeamlessRoot(provider auth.SeamlessProvider) func(c *gin.Context) {
	return func(c *gin.Context) {
		// Check if we have a session already
		profile := s.getProfileFromContext(c)
		if profile == nil {
			// Try to authenticate with the seamless auth
			var err error
			profile, err = provider.SeamlessAuth(c.Request)
			if err != nil {
				c.Set("log-message", "Seamless authentication failed: "+err.Error())
				s.metrics.RecordAuthentication(false)
				s.deleteSessionCookie(c)
				AbortWithError(c, NewResponseError(http.StatusUnauthorized, "Not authenticated"))
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

			// We need to do a redirect to be able to have the cookies actually set
			// Also see: https://github.com/traefik/traefik/issues/3660
			returnURL := getReturnURL(c)
			c.Header("Location", returnURL)
			c.Header("Content-Type", "text/plain; charset=utf-8")
			c.Writer.WriteHeader(http.StatusSeeOther)
			_, _ = c.Writer.WriteString(`Redirecting to application: ` + returnURL)
		}

		// If we are here, we have a valid session, so respond with a 200 status code
		// Include the user name in the response body in case a visitor is hitting the auth server directly
		s.metrics.RecordAuthentication(true)
		user := s.auth.UserIDFromProfile(profile)
		c.Header("X-Forwarded-User", user)
		c.Header("X-Forwarded-Email", profile.GetEmail())
		c.Header("Content-Type", "text/plain; charset=utf-8")
		_, _ = c.Writer.WriteString("You're authenticated as '" + user + "'")
	}
}
