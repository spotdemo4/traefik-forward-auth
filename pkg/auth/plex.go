package auth

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/italypaleale/traefik-forward-auth/pkg/user"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
)

type Plex struct {
	PlexProvider
	clientID     string
	clientName   string
	token        string
	serverID     string
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
	// Plex Server ID
	ServerID string
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

	return &Plex{
		clientID:     opts.ClientID,
		token:        opts.Token,
		serverID:     opts.ServerID,
		allowedUsers: opts.AllowedUsers,

		httpClient: httpClient,
	}, nil
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

type plexServers struct {
	MediaContainer struct {
		Server []struct {
			Name              string `json:"name"`
			MachineIdentifier string `json:"machineIdentifier"`
		} `json:"Server"`
	} `json:"MediaContainer"`
}

func (a *Plex) plexRetrieveServers(token *PlexToken) (*plexServers, error) {
	type plexServersReq struct {
		Token string `json:"X-Plex-Token"`
	}
	jsonReq, err := json.Marshal(plexServersReq{
		Token: token.AuthToken,
	})
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", "https://plex.tv/api/v2/servers", bytes.NewReader(jsonReq))
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

	var servers *plexServers
	err = json.Unmarshal(body, servers)
	if err != nil {
		return nil, err
	}

	return servers, nil
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

	// Also get servers
	servers, err := a.plexRetrieveServers(token)
	if err != nil {
		return nil, err
	}

	serverClaims := map[string]string{}
	for _, server := range servers.MediaContainer.Server {
		serverClaims["server_"+server.Name] = server.MachineIdentifier
	}

	profile := user.Profile{
		ID: pUser.Username,
		Name: user.ProfileName{
			FullName: pUser.Name,
		},
		Email: &user.ProfileEmail{
			Value: pUser.Email,
		},
		Picture:          pUser.Thumb,
		Locale:           pUser.Locale,
		AdditionalClaims: serverClaims,
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
	// Check allowed users
	if len(a.allowedUsers) > 0 && !slices.Contains(a.allowedUsers, profile.ID) {
		return errors.New("user ID is not in the allowlist")
	}

	// Check server
	if a.serverID != "" {
		found := false
		for k, v := range profile.AdditionalClaims {
			if strings.HasPrefix(k, "server_") {
				if v == a.serverID {
					found = true
					break
				}
			}
		}

		if !found {
			return errors.New("user does not belong to server")
		}
	}

	return nil
}
