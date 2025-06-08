package server

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/italypaleale/traefik-forward-auth/pkg/auth"
	"github.com/italypaleale/traefik-forward-auth/pkg/config"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

// handler for GET /
// Respond with 200, or redirect to oauth
func (s *Server) PlexRoot(provider auth.PlexProvider) func(c *gin.Context) {
	return func(c *gin.Context) {
		// Check if we have a session
		profile := s.getProfileFromContext(c)
		if profile != nil {
			// If we are here, we have a valid session, so respond with a 200 status code
			// Include the user name in the response body in case a visitor is hitting the auth server directly
			s.metrics.RecordAuthentication(true)
			user := s.auth.UserIDFromProfile(profile)
			c.Header("X-Forwarded-User", user)
			c.Data(http.StatusOK, "text/plain; charset=utf-8", []byte(`You're authenticated as '`+user+`'`))
			return
		}

		s.metrics.RecordAuthentication(false)

		// Get the return URL
		returnURL := getReturnURL(c)

		// Get plex pin
		pin, err := provider.PlexRetrievePin()
		if err != nil {
			AbortWithError(c, fmt.Errorf("failed to get plex pin: %w", err))
			return
		}

		// Set pin as cookie
		err = s.setPlexCookie(c, pin, returnURL)
		if err != nil {
			AbortWithError(c, fmt.Errorf("failed to set plex cookie: %w", err))
			return
		}

		// Redirect to the authorization URL
		authURL, err := provider.PlexAuthorizeURL(pin.Code, getOAuth2RedirectURI(c))
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
func (s *Server) PlexCallback(provider auth.PlexProvider) func(c *gin.Context) {
	return func(c *gin.Context) {
		// Get plex cookie
		pin, returnURL, err := s.getPlexCookie(c)
		if err != nil {
			AbortWithError(c, NewResponseError(http.StatusUnauthorized, "Bad cookie"))
			return
		}

		// Clear the state cookie
		s.deleteStateCookies(c)

		// Validate pin
		token, err := provider.PlexRetrieveToken(pin)
		if err != nil {
			AbortWithError(c, fmt.Errorf("failed to exchange pin for token: %w", err))
			return
		}

		// Retrieve the user profile
		profile, err := provider.PlexRetrieveProfile(token)
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

func (s *Server) setPlexCookie(c *gin.Context, pin auth.PlexPin, returnURL string) (err error) {
	cfg := config.Get()
	expiration := cfg.AuthenticationTimeout

	// Claims for the JWT
	now := time.Now()
	token, err := jwt.NewBuilder().
		Issuer(jwtIssuer+"/"+s.auth.GetProviderName()).
		Audience([]string{cfg.Hostname}).
		IssuedAt(now).
		// Add 1 extra second to synchronize with cookie expiry
		Expiration(now.Add(expiration+time.Second)).
		NotBefore(now).
		Claim("id", pin.ID).
		Claim("code", pin.Code).
		Claim("return_url", returnURL).
		Build()
	if err != nil {
		return fmt.Errorf("failed to build JWT: %w", err)
	}

	// Generate the JWT
	cookieValue, err := jwt.NewSerializer().
		Sign(jwt.WithKey(jwa.HS256, cfg.GetTokenSigningKey())).
		Serialize(token)
	if err != nil {
		return fmt.Errorf("failed to serialize token: %w", err)
	}

	// Set the cookie
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie(stateCookieNamePrefix+"plex", string(cookieValue), int(expiration.Seconds())-1, "/", cfg.CookieDomain, !cfg.CookieInsecure, true)

	return nil
}

func (s *Server) getPlexCookie(c *gin.Context) (pin auth.PlexPin, returnURL string, err error) {
	cfg := config.Get()

	// Get the cookie
	cookieValue, err := c.Cookie(stateCookieNamePrefix + "plex")
	if errors.Is(err, http.ErrNoCookie) {
		return pin, "", nil
	} else if err != nil {
		return pin, "", fmt.Errorf("failed to get cookie: %w", err)
	}
	if cookieValue == "" {
		return pin, "", fmt.Errorf("cookie %s is empty", cfg.CookieName)
	}

	// Parse the JWT in the cookie
	token, err := jwt.Parse([]byte(cookieValue),
		jwt.WithAcceptableSkew(acceptableClockSkew),
		jwt.WithIssuer(jwtIssuer+"/"+s.auth.GetProviderName()),
		jwt.WithAudience(cfg.Hostname),
		jwt.WithKey(jwa.HS256, cfg.GetTokenSigningKey()),
	)
	if err != nil {
		return pin, "", fmt.Errorf("failed to parse JWT: %w", err)
	}

	// Get the plex pin
	idAny, _ := token.Get("id")
	id, _ := idAny.(int)
	if id == 0 {
		return pin, "", errors.New("claim 'id' not found in JWT")
	}
	codeAny, _ := token.Get("code")
	code, _ := codeAny.(string)
	if code == "" {
		return pin, "", errors.New("claim 'code' not found in JWT")
	}
	pin = auth.PlexPin{
		ID:   id,
		Code: code,
	}

	// Get the return URL
	returnURLAny, _ := token.Get("return_url")
	returnURL, _ = returnURLAny.(string)
	if returnURL == "" {
		return pin, "", errors.New("claim 'return_url' not found in JWT")
	}

	return pin, returnURL, nil
}
