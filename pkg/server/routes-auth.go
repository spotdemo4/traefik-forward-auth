package server

import (
	"crypto/sha256"
	"encoding/base64"
	"net/url"

	"github.com/gin-gonic/gin"
	"github.com/italypaleale/traefik-forward-auth/pkg/config"
	"github.com/italypaleale/traefik-forward-auth/pkg/user"
)

// RouteGetLogout is the handler for GET /logout
// This removes the session cookie
func (s *Server) RouteGetLogout(c *gin.Context) {
	// Delete the state and session cookies
	s.deleteSessionCookie(c)
	s.deleteStateCookies(c)

	// Respond with a success message
	c.Header("Content-Type", "text/plain; charset=utf-8")
	_, _ = c.Writer.WriteString("You've logged out")
}

func (s *Server) getProfileFromContext(c *gin.Context) *user.Profile {
	if !c.GetBool("session-auth") {
		return nil
	}
	profileAny, ok := c.Get("session-profile")
	if !ok {
		return nil
	}
	profile, ok := profileAny.(*user.Profile)
	if !ok || profile == nil || profile.ID == "" {
		return nil
	}
	return profile
}

// Get the return URL, to redirect users to after a successful auth
func getReturnURL(c *gin.Context) string {
	// Here we use  X-Forwarded-* headers which have the data of the original request
	reqURL := c.Request.URL
	if slice, ok := c.Request.Header["X-Forwarded-Uri"]; ok {
		var val string
		if len(slice) > 0 {
			val = slice[0]
		}
		reqURL, _ = url.Parse(val)
	}
	return c.Request.Header.Get("X-Forwarded-Proto") + "://" + c.Request.Header.Get("X-Forwarded-Host") + reqURL.Path
}

// Computes the state cookie ID for the given return URL
func getStateCookieID(returnURL string) string {
	h := sha256.New()
	h.Write([]byte("tf_return_url:"))
	h.Write([]byte(returnURL))
	digest := h.Sum(nil)

	return base64.RawURLEncoding.EncodeToString(digest[:8])
}

// Get the redirect URI, which is sent to the OAuth2 authentication server and indicates where to return users after a successful auth with the IdP
func getRedirectURI(c *gin.Context) string {
	cfg := config.Get()
	return c.GetHeader("X-Forwarded-Proto") + "://" + cfg.Hostname + cfg.BasePath + "/oauth2/callback"
}
