package auth

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
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
	allowFriends bool
	allowedUsers []string

	httpClient *http.Client
}

type PlexPin struct {
	ID   string `json:"id"`
	Code string `json:"code"`
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
	_, err := plex.PlexRetrieveProfile(opts.Token)
	if err != nil {
		return nil, errors.New("invalid token for provider 'plex': " + err.Error())
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

func (a *Plex) PlexRetrievePin() (*PlexPin, error) {
	formReq := url.Values{
		"strong":                   []string{"true"},
		"X-Plex-Product":           []string{a.clientName},
		"X-Plex-Client-Identifier": []string{a.clientID},
	}.Encode()

	log := slog.Default()
	log.Info("Sending", "req", formReq)

	req, err := http.NewRequest("POST", "https://plex.tv/api/v2/pins", strings.NewReader(formReq))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
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

func (a *Plex) PlexRetrieveToken(pin *PlexPin) (string, error) {
	formReq := url.Values{
		"code":                     []string{pin.Code},
		"X-Plex-Client-Identifier": []string{a.clientID},
	}.Encode()

	req, err := http.NewRequest("GET", "https://plex.tv/api/v2/pins/"+pin.ID, strings.NewReader(formReq))
	if err != nil {
		return "", err
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := a.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	type plexToken struct {
		Token string `json:"authToken"`
	}
	var token plexToken
	err = json.Unmarshal(body, &token)
	if err != nil {
		return "", err
	}

	if token.Token == "" {
		return "", errors.New("pin did not contain token")
	}

	return token.Token, err
}

type plexFriend struct {
	Username string `json:"username"`
}

func (a *Plex) plexRetrieveFriends() ([]plexFriend, error) {
	formReq := url.Values{
		"X-Plex-Token": []string{a.token},
	}.Encode()

	req, err := http.NewRequest("GET", "https://plex.tv/api/v2/friends", strings.NewReader(formReq))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
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

func (a *Plex) PlexRetrieveProfile(token string) (*user.Profile, error) {
	formReq := url.Values{
		"X-Plex-Token":             []string{token},
		"X-Plex-Product":           []string{a.clientName},
		"X-Plex-Client-Identifier": []string{a.clientID},
	}.Encode()

	log := slog.Default()
	log.Info("Sending", "req", formReq)

	req, err := http.NewRequest("GET", "https://plex.tv/api/v2/user", strings.NewReader(formReq))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	log.Info("Received", "resp", body)

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
