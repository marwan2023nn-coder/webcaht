// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See LICENSE.txt for license information.

package platform

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/golang-jwt/jwt/v5"
	"github.com/mattermost/mattermost/server/public/model"
	"github.com/mattermost/mattermost/server/public/shared/mlog"
	"github.com/mattermost/mattermost/server/v8/channels/utils"
	"github.com/mattermost/mattermost/server/v8/einterfaces"
)

const (
	LicenseEnv = "MM_LICENSE"
)

// JWTClaims custom JWT claims with the needed information for the
// renewal process
type JWTClaims struct {
	LicenseID   string `json:"license_id"`
	ActiveUsers int64  `json:"active_users"`
	jwt.RegisteredClaims
}

func (ps *PlatformService) LicenseManager() einterfaces.LicenseInterface {
	return ps.licenseManager
}

func (ps *PlatformService) SetLicenseManager(impl einterfaces.LicenseInterface) {
	ps.licenseManager = impl
}

func (ps *PlatformService) License() *model.License {
	ps.fakeLicenseOnce.Do(func() {
		now := model.GetMillis()

		// p returns a pointer to a bool — inline helper, allocated once
		p := func(b bool) *bool { return model.NewPointer(b) }
		// n returns a pointer to an int
		n := func(i int) *int { return model.NewPointer(i) }

		// 100 years in milliseconds — guarantees IsExpired() and IsPastGracePeriod() never fire
		hundredYearsMs := int64(1000 * 60 * 60 * 24 * 365 * 100)

		ps.fakeLicenseCache = &model.License{
			// model.NewId() generates a unique 26-char ULID — called once at startup
			Id:       model.NewId(),
			IssuedAt: now,
			StartsAt: now,
			// 100 years: IsExpired() → false, IsPastGracePeriod() → false, DaysToExpiration() → 36500
			ExpiresAt: now + hundredYearsMs,

			// IsTrial=false prevents IsTrialLicense() from returning true
			// (which would activate trial-specific restrictions in some paths)
			IsTrial:             false,
			IsGovSku:            false,
			IsSeatCountEnforced: false,

			Customer: &model.Customer{
				Id:      model.NewId(),
				Name:    "marwan",
				Email:   "marwan@workspace.com",
				Company: "workspace",
			},

			// All Features fields from model.Features struct — none omitted.
			// FutureFeatures=true ensures any future feature gating defaults to enabled.
			Features: &model.Features{
				Users: n(1000000),

				// Authentication & SSO
				LDAP:           p(true),
				LDAPGroups:     p(true),
				MFA:            p(true),
				GoogleOAuth:    p(true),
				Office365OAuth: p(true),
				OpenId:         p(true),
				SAML:           p(true),

				// Compliance & Data
				Compliance:               p(true),
				DataRetention:            p(true),
				MessageExport:            p(true),
				CustomPermissionsSchemes: p(true),
				CustomTermsOfService:     p(true),

				// Infrastructure
				Cluster:       p(true),
				Metrics:       p(true),
				Elasticsearch: p(true),

				// Messaging & Notifications
				MHPNS:                     p(true),
				IDLoadedPushNotifications: p(true),
				EmailNotificationContents: p(true),
				Announcement:              p(true),
				AutoTranslation:           p(true),

				// Guest & Permissions
				GuestAccounts:            p(true),
				GuestAccountsPermissions: p(true),
				LockTeammateNameDisplay:  p(true),

				// UI & Themes
				ThemeManagement: p(true),

				// Enterprise Plugins & Integrations
				EnterprisePlugins:        p(true),
				AdvancedLogging:          p(true),
				OutgoingOAuthConnections: p(true),

				// Shared / Remote Channels
				SharedChannels:       p(true),
				RemoteClusterService: p(true),

				// Cloud — intentionally false: prevents cloud-specific code paths
				// that assume a different billing/infra model
				Cloud: p(false),

				// Future-proof: any new feature gated on FutureFeatures will be enabled
				FutureFeatures: p(true),
			},

			SkuName:      "Workspace Enterprise Advanced",
			SkuShortName: model.LicenseShortSkuEnterpriseAdvanced, // "advanced"
		}

		// Ensure all nil feature fields get safe defaults (defensive call)
		ps.fakeLicenseCache.Features.SetDefaults()
	})
	return ps.fakeLicenseCache
}

// IsLicenseActive returns true if there is a valid, non-expired license.
// This is a high-performance check used in time-critical paths like posting.
func (ps *PlatformService) IsLicenseActive() bool {
	lic := ps.licenseValue.Load()
	if lic == nil {
		return false
	}
	// The virtual license never expires (100 years).
	// Real licenses will return the correct status based on their expiry.
	return !lic.IsExpired()
}

func (ps *PlatformService) LoadLicense() {
	// Check if the license was explicitly removed by an admin.
	// If so, do NOT load the virtual license or databases-stored license.
	if removed, err := ps.Store.System().GetByName("LicenseRemoved"); err == nil && removed != nil && removed.Value == "true" {
		ps.SetLicense(nil)
		ps.logger.Info("Sofa Workspace: License remains removed (persistent state).")
		return
	}

	// Check if a real license was saved to the database
	if licenseStr, err := ps.Store.System().GetByName("License"); err == nil && licenseStr != nil && licenseStr.Value != "" {
		if license, appErr := utils.LicenseValidator.LicenseFromBytes([]byte(licenseStr.Value)); appErr == nil {
			ps.SetLicense(license)
			ps.logger.Info("Sofa Workspace: Loaded saved license from database.",
				mlog.String("sku", license.SkuName),
				mlog.String("expires_at", model.GetTimeForMillis(license.ExpiresAt).String()),
			)
			return
		}
	}
	// Fallback: activate the virtual Enterprise license.
	license := ps.License()
	ps.SetLicense(license)
	ps.logger.Info("Sofa Workspace: Virtual Enterprise license activated.",
		mlog.String("sku", license.SkuName),
		mlog.String("expires_at", model.GetTimeForMillis(license.ExpiresAt).String()),
	)
}

// SaveLicense parses uploaded license bytes and saves them to the database.
// If valid, it applies the license immediately. On failure, falls back to virtual license.
func (ps *PlatformService) SaveLicense(licenseBytes []byte) (*model.License, *model.AppError) {
	if len(licenseBytes) == 0 {
		return ps.License(), nil
	}

	license, appErr := utils.LicenseValidator.LicenseFromBytes(licenseBytes)
	if appErr != nil {
		ps.logger.Warn("SaveLicense: failed to parse uploaded license, using virtual license", mlog.Err(appErr))
		return ps.License(), nil
	}

	// Persist to the database so the license survives server restarts
	_ = ps.Store.System().SaveOrUpdate(&model.System{Name: "License", Value: string(licenseBytes)})

	// Clear the "removed" flag since we are now installing a valid license
	_, _ = ps.Store.System().PermanentDeleteByName("LicenseRemoved")

	// Apply the uploaded license so the frontend reflects it
	ps.SetLicense(license)
	ps.logger.Info("SaveLicense: uploaded license applied and persisted",
		mlog.String("sku", license.SkuName),
		mlog.String("id", license.Id),
	)
	return license, nil
}

func (ps *PlatformService) SetLicense(license *model.License) bool {
	oldLicense := ps.licenseValue.Load()
	defer func() {
		for _, listener := range ps.licenseListeners {
			listener(oldLicense, license)
		}
	}()

	if license != nil {
		license.Features.SetDefaults()
		ps.licenseValue.Store(license)
		ps.clientLicenseValue.Store(utils.GetClientLicense(license))
		if oldLicense == nil || oldLicense.Id != license.Id {
			ps.logLicense("Set license", license)
		}
		return true
	}

	ps.licenseValue.Store((*model.License)(nil))
	ps.clientLicenseValue.Store(map[string]string(nil))
	return false
}

func (ps *PlatformService) ValidateAndSetLicenseBytes(_ []byte) error {
	// Always install the fake license, bypassing any signature or content validation.
	ps.SetLicense(ps.License())
	return nil
}

func (ps *PlatformService) SetClientLicense(m map[string]string) {
	ps.clientLicenseValue.Store(m)
}

func (ps *PlatformService) ClientLicense() map[string]string {
	// Use IsLicenseActive to quickly determine if we should return feature flags.
	if ps.IsLicenseActive() {
		if clientLicense, _ := ps.clientLicenseValue.Load().(map[string]string); clientLicense != nil {
			return clientLicense
		}
		// Fallback for initial startup before clientLicenseValue is populated.
		return utils.GetClientLicense(ps.License())
	}

	// If no active license (removed or expired), return unlicensed state.
	return map[string]string{"IsLicensed": "false"}
}

func (ps *PlatformService) RemoveLicense() *model.AppError {
	// Use SetLicense(nil) to clear license state so that post/file checks enforce restrictions
	ps.SetLicense(nil)
	ps.logger.Info("Sofa Workspace: License removed. Posts and file uploads are now blocked.")

	// Persist the "removed" state so it survives server restarts
	_ = ps.Store.System().SaveOrUpdate(&model.System{Name: "LicenseRemoved", Value: "true"})

	// Also clear the saved license from the database
	_, _ = ps.Store.System().PermanentDeleteByName("License")
	return nil
}

func (ps *PlatformService) AddLicenseListener(listener func(oldLicense, newLicense *model.License)) string {
	id := model.NewId()
	ps.licenseListeners[id] = listener
	return id
}

func (ps *PlatformService) RemoveLicenseListener(id string) {
	delete(ps.licenseListeners, id)
}

func (ps *PlatformService) GetSanitizedClientLicense() map[string]string {
	return utils.GetSanitizedClientLicense(ps.ClientLicense())
}

// RequestTrialLicense request a trial license from the mattermost official license server
func (ps *PlatformService) RequestTrialLicense(trialRequest *model.TrialLicenseRequest) *model.AppError {
	trialRequestJSON, err := json.Marshal(trialRequest)
	if err != nil {
		return model.NewAppError("RequestTrialLicense", "api.unmarshal_error", nil, "", http.StatusInternalServerError).Wrap(err)
	}

	resp, err := http.Post(ps.getRequestTrialURL(), "application/json", bytes.NewBuffer(trialRequestJSON))
	if err != nil {
		return model.NewAppError("RequestTrialLicense", "api.license.request_trial_license.app_error", nil, "", http.StatusBadRequest).Wrap(err)
	}
	defer resp.Body.Close()

	// CloudFlare sitting in front of the Customer Portal will block this request with a 451 response code in the event that the request originates from a country sanctioned by the U.S. Government.
	if resp.StatusCode == http.StatusUnavailableForLegalReasons {
		return model.NewAppError("RequestTrialLicense", "api.license.request_trial_license.embargoed", nil, "Request for trial license came from an embargoed country", http.StatusUnavailableForLegalReasons)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return model.NewAppError("RequestTrialLicense", "api.license.request_trial_license.app_error", nil,
			fmt.Sprintf("Unexpected HTTP status code %q returned by server", resp.Status), http.StatusInternalServerError)
	}

	var licenseResponse map[string]string
	err = json.NewDecoder(resp.Body).Decode(&licenseResponse)
	if err != nil {
		ps.logger.Warn("Error decoding license response", mlog.Err(err))
	}

	if _, ok := licenseResponse["license"]; !ok {
		return model.NewAppError("RequestTrialLicense", "api.license.request_trial_license.app_error", nil, licenseResponse["message"], http.StatusBadRequest)
	}

	if _, err := ps.SaveLicense([]byte(licenseResponse["license"])); err != nil {
		return err
	}

	if err := ps.ReloadConfig(); err != nil {
		ps.logger.Warn("Failed to reload config after requesting trial license", mlog.Err(err))
	}
	if appErr := ps.InvalidateAllCaches(); appErr != nil {
		ps.logger.Warn("Failed to invalidate cache after requesting trial license", mlog.Err(appErr))
	}

	return nil
}

func (ps *PlatformService) getRequestTrialURL() string {
	return fmt.Sprintf("%s/api/v1/trials", *ps.Config().CloudSettings.CWSURL)
}

func (ps *PlatformService) logLicense(message string, license *model.License) {
	if ps.logger == nil {
		return
	}

	logger := ps.logger.With(
		mlog.String("id", license.Id),
		mlog.Time("issued_at", model.GetTimeForMillis(license.IssuedAt)),
		mlog.Time("starts_at", model.GetTimeForMillis(license.StartsAt)),
		mlog.Time("expires_at", model.GetTimeForMillis(license.ExpiresAt)),
		mlog.String("sku_name", license.SkuName),
		mlog.String("sku_short_name", license.SkuShortName),
		mlog.Bool("is_trial", license.IsTrial),
		mlog.Bool("is_gov_sku", license.IsGovSku),
	)

	if license.Customer != nil {
		logger = logger.With(mlog.String("customer_id", license.Customer.Id))
	}

	if license.Features != nil {
		logger = logger.With(
			mlog.Int("features.users", *license.Features.Users),
			mlog.Map("features", license.Features.ToMap()),
		)
	}

	logger.Info(message)
}
