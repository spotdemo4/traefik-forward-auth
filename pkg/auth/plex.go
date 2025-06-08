package auth

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"time"

	"github.com/italypaleale/traefik-forward-auth/pkg/user"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
)

type Plex struct {
	PlexProvider
	clientID     string
	clientName   string
	token        string
	allowFriends bool
	allowedUsers []string

	httpClient *http.Client
}

type PlexPin struct {
	ID   string `json:"id"`
	Code string `json:"code"`
}

type PlexToken struct {
	AuthToken string    `json:"authToken"`
	ExpiresAt time.Time `json:"expiresAt"`
}

type NewPlexOptions struct {
	// Client ID
	ClientID string
	// Client Name
	ClientName string
	// Plex Token
	Token string
	// Allow plex friends
	AllowFriends bool
	// If non-empty, allows these user accounts only
	AllowedUsers []string
	// Request timeout; defaults to 10s
	RequestTimeout time.Duration
}

func NewPlex(opts NewPlexOptions) (*Plex, error) {
	if opts.ClientID == "" {
		return nil, errors.New("value for clientId is required in config for auth with provider 'plex'")
	}
	if opts.ClientName == "" {
		return nil, errors.New("value for clientName is required in config for auth with provider 'plex'")
	}
	if opts.Token == "" {
		return nil, errors.New("value for token is required in config for auth with provider 'plex'")
	}
	reqTimeout := opts.RequestTimeout
	if reqTimeout < time.Second {
		reqTimeout = 10 * time.Second
	}

	// Update the transport for the HTTP client to include tracing information
	httpClient := &http.Client{
		Timeout: reqTimeout,
	}
	httpClient.Transport = otelhttp.NewTransport(httpClient.Transport)

	plex := Plex{
		clientID:     opts.ClientID,
		clientName:   opts.ClientName,
		token:        opts.Token,
		allowFriends: opts.AllowFriends,
		allowedUsers: opts.AllowedUsers,

		httpClient: httpClient,
	}

	// Validate token
	_, err := plex.PlexRetrieveProfile(&PlexToken{
		AuthToken: opts.Token,
	})
	if err != nil {
		return nil, errors.New("invalid token for provider 'plex'")
	}

	return &plex, nil
}

func (a *Plex) PlexAuthorizeURL(code string, redirectURL string) (string, error) {
	if code == "" {
		return "", errors.New("parameter code is required")
	}

	params := url.Values{
		"clientID":                         []string{a.clientID},
		"code":                             []string{code},
		"forwardUrl":                       []string{redirectURL},
		"context%5Bdevice%5D%5Bproduct%5D": []string{a.clientName},
	}

	return "https://app.plex.tv/auth#" + "?" + params.Encode(), nil
}

type plexPinReq struct {
	Strong   bool   `json:"strong"`
	Product  string `json:"X-Plex-Product"`
	ClientID string `json:"X-Plex-Client-Identifier"`
}

func (a *Plex) PlexRetrievePin() (*PlexPin, error) {
	jsonReq, err := json.Marshal(plexPinReq{
		Strong:   true,
		Product:  a.clientName,
		ClientID: a.clientID,
	})
	if err != nil {
		return nil, err
	}

	log := slog.Default()
	log.Info("Sending", "req", jsonReq)

	req, err := http.NewRequest("POST", "https://plex.tv/api/v2/pins", bytes.NewReader(jsonReq))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	log.Info("Received", "resp", string(body))

	var pin *PlexPin
	err = json.Unmarshal(body, pin)
	if err != nil {
		return nil, err
	}

	return pin, err
}

func (a *Plex) PlexRetrieveToken(pin *PlexPin) (*PlexToken, error) {
	type plexTokenReq struct {
		Code     string `json:"code"`
		ClientID string `json:"X-Plex-Client-Identifier"`
	}
	jsonReq, err := json.Marshal(plexTokenReq{
		Code:     pin.Code,
		ClientID: a.clientID,
	})
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", "https://plex.tv/api/v2/pins/"+pin.ID, bytes.NewReader(jsonReq))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var token *PlexToken
	err = json.Unmarshal(body, token)
	if err != nil {
		return nil, err
	}

	return token, err
}

type plexFriend struct {
	Username string `json:"username"`
}

func (a *Plex) plexRetrieveFriends() ([]plexFriend, error) {
	type plexServersReq struct {
		Token string `json:"X-Plex-Token"`
	}
	jsonReq, err := json.Marshal(plexServersReq{
		Token: a.token,
	})
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", "https://plex.tv/api/v2/friends", bytes.NewReader(jsonReq))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var friends []plexFriend
	err = json.Unmarshal(body, &friends)
	if err != nil {
		return nil, err
	}

	return friends, nil
}

func (a *Plex) PlexRetrieveProfile(token *PlexToken) (*user.Profile, error) {
	type plexProfileReq struct {
		Token    string `json:"X-Plex-Token"`
		Product  string `json:"X-Plex-Product"`
		ClientID string `json:"X-Plex-Client-Identifier"`
	}
	jsonReq, err := json.Marshal(plexProfileReq{
		Token:    token.AuthToken,
		Product:  a.clientName,
		ClientID: a.clientID,
	})
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", "https://plex.tv/api/v2/user", bytes.NewReader(jsonReq))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	type plexUser struct {
		Username string `json:"username"`
		Name     string `json:"friendlyName"`
		Email    string `json:"email"`
		Thumb    string `json:"thumb"`
		Locale   string `json:"locale"`
	}
	var pUser plexUser
	err = json.Unmarshal(body, &pUser)
	if err != nil {
		return nil, err
	}

	profile := user.Profile{
		ID: pUser.Username,
		Name: user.ProfileName{
			FullName: pUser.Name,
		},
		Email: &user.ProfileEmail{
			Value: pUser.Email,
		},
		Picture: pUser.Thumb,
		Locale:  pUser.Locale,
	}

	return &profile, err
}

func (a *Plex) GetProviderName() string {
	return "plex"
}

func (a *Plex) UserIDFromProfile(profile *user.Profile) string {
	return profile.ID
}

func (a *Plex) ValidateRequestClaims(r *http.Request, profile *user.Profile) error {
	return nil
}

func (a *Plex) PopulateAdditionalClaims(claims map[string]any, setClaimFn func(key, val string)) {
	// ...
}

func (a *Plex) UserAllowed(profile *user.Profile) error {
	// Default to allow all
	if len(a.allowedUsers) == 0 && !a.allowFriends {
		return nil
	}

	// Check allowed users
	if slices.Contains(a.allowedUsers, profile.ID) {
		return nil
	}

	// Check friends
	if a.allowFriends {
		friends, err := a.plexRetrieveFriends()
		if err != nil {
			return err
		}

		for _, friend := range friends {
			if friend.Username == profile.ID {
				return nil
			}
		}
	}

	return errors.New("could not authenticate user")
}
