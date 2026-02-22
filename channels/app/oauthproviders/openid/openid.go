// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See LICENSE.txt for license information.

package oauthopenid

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/mattermost/mattermost/server/public/model"
	"github.com/mattermost/mattermost/server/public/shared/mlog"
	"github.com/mattermost/mattermost/server/public/shared/request"
	"github.com/mattermost/mattermost/server/v8/einterfaces"
)

type OpenIDProvider struct {
	discoveryCache sync.Map
}

type OpenIDUser struct {
	Sub               string `json:"sub"`
	Email             string `json:"email"`
	PreferredUsername string `json:"preferred_username"`
	Nickname          string `json:"nickname"`
	Name              string `json:"name"`
	GivenName         string `json:"given_name"`
	FamilyName        string `json:"family_name"`
}

type DiscoveryResponse struct {
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserInfoEndpoint      string `json:"userinfo_endpoint"`
}

func init() {
	provider := &OpenIDProvider{}
	einterfaces.RegisterOAuthProvider(model.ServiceOpenid, provider)
}

func userFromOpenIDUser(logger mlog.LoggerIFace, oiu *OpenIDUser) *model.User {
	user := &model.User{}
	username := oiu.PreferredUsername
	if username == "" {
		username = oiu.Nickname
	}
	if username == "" {
		username = oiu.Name
	}
	if username == "" {
		username = oiu.Email
	}

	user.Username = model.CleanUsername(logger, username)

	if oiu.GivenName != "" {
		user.FirstName = oiu.GivenName
		user.LastName = oiu.FamilyName
	} else if oiu.Name != "" {
		splitName := strings.Split(oiu.Name, " ")
		if len(splitName) >= 2 {
			user.FirstName = splitName[0]
			user.LastName = strings.Join(splitName[1:], " ")
		} else {
			user.FirstName = oiu.Name
		}
	}

	user.Email = oiu.Email
	user.Email = strings.ToLower(user.Email)
	user.AuthData = &oiu.Sub
	user.AuthService = model.ServiceOpenid

	return user
}

func openIDUserFromJSON(data io.Reader) (*OpenIDUser, error) {
	decoder := json.NewDecoder(data)
	var oiu OpenIDUser
	err := decoder.Decode(&oiu)
	if err != nil {
		return nil, err
	}
	return &oiu, nil
}

func (oiu *OpenIDUser) IsValid() error {
	if oiu.Sub == "" {
		return errors.New("user sub can't be empty")
	}

	if oiu.Email == "" {
		return errors.New("user e-mail should not be empty")
	}

	return nil
}

func (gp *OpenIDProvider) GetUserFromJSON(rctx request.CTX, data io.Reader, tokenUser *model.User) (*model.User, error) {
	oiu, err := openIDUserFromJSON(data)
	if err != nil {
		return nil, err
	}
	if err = oiu.IsValid(); err != nil {
		return nil, err
	}

	return userFromOpenIDUser(rctx.Logger(), oiu), nil
}

func (gp *OpenIDProvider) GetSSOSettings(rctx request.CTX, config *model.Config, service string) (*model.SSOSettings, error) {
	sso := config.OpenIdSettings

	// Robustness: trim leading/trailing whitespace from ID and Secret
	if sso.Id != nil {
		id := strings.TrimSpace(*sso.Id)
		sso.Id = &id
	}
	if sso.Secret != nil {
		secret := strings.TrimSpace(*sso.Secret)
		sso.Secret = &secret
	}

	if *sso.Enable && *sso.DiscoveryEndpoint != "" && (*sso.AuthEndpoint == "" || *sso.TokenEndpoint == "" || *sso.UserAPIEndpoint == "") {
		discoveryURL := *sso.DiscoveryEndpoint

		var discovery DiscoveryResponse
		if val, ok := gp.discoveryCache.Load(discoveryURL); ok {
			discovery = val.(DiscoveryResponse)
		} else {
			client := http.Client{Timeout: 5 * time.Second}
			resp, err := client.Get(discoveryURL)
			if err != nil {
				return nil, err
			}
			defer resp.Body.Close()
			if err := json.NewDecoder(resp.Body).Decode(&discovery); err != nil {
				return nil, err
			}
			gp.discoveryCache.Store(discoveryURL, discovery)
		}

		// Patch the settings for this request
		if *sso.AuthEndpoint == "" {
			sso.AuthEndpoint = &discovery.AuthorizationEndpoint
		}
		if *sso.TokenEndpoint == "" {
			sso.TokenEndpoint = &discovery.TokenEndpoint
		}
		if *sso.UserAPIEndpoint == "" {
			sso.UserAPIEndpoint = &discovery.UserInfoEndpoint
		}
	}
	return &sso, nil
}

func (gp *OpenIDProvider) GetUserFromIdToken(_ request.CTX, idToken string) (*model.User, error) {
	return nil, nil
}

func (gp *OpenIDProvider) IsSameUser(_ request.CTX, dbUser, oauthUser *model.User) bool {
	return dbUser.AuthData == oauthUser.AuthData
}
