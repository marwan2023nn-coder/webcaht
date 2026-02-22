// generate_license: Generates RSA key pair and a signed Workspace Enterprise license file.
package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"time"
)

// Mirror minimal model types needed (no server import dependency)
type Customer struct {
	Id      string `json:"id"`
	Name    string `json:"name"`
	Email   string `json:"email"`
	Company string `json:"company"`
}

type Features struct {
	Users                     *int  `json:"Users"`
	LDAP                      *bool `json:"LDAP"`
	LDAPGroups                *bool `json:"LDAPGroups"`
	MFA                       *bool `json:"MFA"`
	GoogleOAuth               *bool `json:"GoogleOAuth"`
	Office365OAuth            *bool `json:"Office365OAuth"`
	OpenId                    *bool `json:"OpenId"`
	SAML                      *bool `json:"SAML"`
	Compliance                *bool `json:"Compliance"`
	DataRetention             *bool `json:"DataRetention"`
	MessageExport             *bool `json:"MessageExport"`
	CustomPermissionsSchemes  *bool `json:"CustomPermissionsSchemes"`
	CustomTermsOfService      *bool `json:"CustomTermsOfService"`
	Cluster                   *bool `json:"Cluster"`
	Metrics                   *bool `json:"Metrics"`
	Elasticsearch             *bool `json:"Elasticsearch"`
	MHPNS                     *bool `json:"MHPNS"`
	IDLoadedPushNotifications *bool `json:"IDLoadedPushNotifications"`
	EmailNotificationContents *bool `json:"EmailNotificationContents"`
	Announcement              *bool `json:"Announcement"`
	AutoTranslation           *bool `json:"AutoTranslation"`
	GuestAccounts             *bool `json:"GuestAccounts"`
	GuestAccountsPermissions  *bool `json:"GuestAccountsPermissions"`
	LockTeammateNameDisplay   *bool `json:"LockTeammateNameDisplay"`
	ThemeManagement           *bool `json:"ThemeManagement"`
	EnterprisePlugins         *bool `json:"EnterprisePlugins"`
	AdvancedLogging           *bool `json:"AdvancedLogging"`
	OutgoingOAuthConnections  *bool `json:"OutgoingOAuthConnections"`
	SharedChannels            *bool `json:"SharedChannels"`
	RemoteClusterService      *bool `json:"RemoteClusterService"`
	Cloud                     *bool `json:"Cloud"`
	FutureFeatures            *bool `json:"FutureFeatures"`
}

type License struct {
	Id           string    `json:"id"`
	IssuedAt     int64     `json:"issued_at"`
	StartsAt     int64     `json:"starts_at"`
	ExpiresAt    int64     `json:"expires_at"`
	Customer     *Customer `json:"customer"`
	Features     *Features `json:"features"`
	SkuName      string    `json:"sku_name"`
	SkuShortName string    `json:"sku_short_name"`
	IsTrial      bool      `json:"is_trial"`
	IsGovSku     bool      `json:"is_gov_sku"`
}

func boolPtr(b bool) *bool { return &b }
func intPtr(i int) *int    { return &i }

func main() {
	var privateKey *rsa.PrivateKey

	// Reuse existing key if available (so all license files stay consistent with server binary)
	if keyBytes, err := os.ReadFile("workspace.private.pem"); err == nil {
		block, _ := pem.Decode(keyBytes)
		if block != nil {
			privateKey, _ = x509.ParsePKCS1PrivateKey(block.Bytes)
		}
	}

	if privateKey == nil {
		fmt.Println("🔑 Generating new RSA-2048 key pair...")
		var err error
		privateKey, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			panic(err)
		}

		// Save private key
		privFile, _ := os.Create("workspace.private.pem")
		pem.Encode(privFile, &pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
		})
		privFile.Close()
		fmt.Println("✅ Private key saved: workspace.private.pem")

		// Save public key in PKIX DER format (matches x509.ParsePKIXPublicKey)
		publicDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
		if err != nil {
			panic(err)
		}
		pubFile, _ := os.Create("workspace.public.pem")
		pem.Encode(pubFile, &pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: publicDER,
		})
		pubFile.Close()
		fmt.Println("✅ Public key saved: workspace.public.pem")
	} else {
		fmt.Println("🔑 Loaded existing RSA key pair from workspace.private.pem")
	}

	// --- Build license JSON ---
	now := time.Now().UnixMilli()
	hundredYears := int64(1000 * 60 * 60 * 24 * 365 * 100)

	license := &License{
		Id:        "workspace-enterprise-advanced-license",
		IssuedAt:  now,
		StartsAt:  now,
		ExpiresAt: now + hundredYears,
		Customer: &Customer{
			Id:      "workspace-customer-001",
			Name:    "marwan",
			Email:   "marwan@workspace.com",
			Company: "workspace",
		},
		Features: &Features{
			Users:                     intPtr(1000000),
			LDAP:                      boolPtr(true),
			LDAPGroups:                boolPtr(true),
			MFA:                       boolPtr(true),
			GoogleOAuth:               boolPtr(true),
			Office365OAuth:            boolPtr(true),
			OpenId:                    boolPtr(true),
			SAML:                      boolPtr(true),
			Compliance:                boolPtr(true),
			DataRetention:             boolPtr(true),
			MessageExport:             boolPtr(true),
			CustomPermissionsSchemes:  boolPtr(true),
			CustomTermsOfService:      boolPtr(true),
			Cluster:                   boolPtr(true),
			Metrics:                   boolPtr(true),
			Elasticsearch:             boolPtr(true),
			MHPNS:                     boolPtr(true),
			IDLoadedPushNotifications: boolPtr(true),
			EmailNotificationContents: boolPtr(true),
			Announcement:              boolPtr(true),
			AutoTranslation:           boolPtr(true),
			GuestAccounts:             boolPtr(true),
			GuestAccountsPermissions:  boolPtr(true),
			LockTeammateNameDisplay:   boolPtr(true),
			ThemeManagement:           boolPtr(true),
			EnterprisePlugins:         boolPtr(true),
			AdvancedLogging:           boolPtr(true),
			OutgoingOAuthConnections:  boolPtr(true),
			SharedChannels:            boolPtr(true),
			RemoteClusterService:      boolPtr(true),
			Cloud:                     boolPtr(false),
			FutureFeatures:            boolPtr(true),
		},
		SkuName:      "Workspace Enterprise Advanced",
		SkuShortName: "advanced",
		IsTrial:      false,
		IsGovSku:     false,
	}

	plaintext, err := json.Marshal(license)
	if err != nil {
		panic(err)
	}
	fmt.Printf("📄 License JSON (%d bytes)\n", len(plaintext))

	// --- Sign with SHA512+RSA (matches server's ValidateLicense) ---
	h := sha512.New()
	h.Write(plaintext)
	digest := h.Sum(nil)

	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA512, digest)
	if err != nil {
		panic(err)
	}

	// --- Build signed blob: plaintext || signature (256 bytes) ---
	signed := append(plaintext, signature...)

	// --- Base64 encode (matches server's base64.StdEncoding.Decode) ---
	encoded := base64.StdEncoding.EncodeToString(signed)

	licenseFile, _ := os.Create("workspace-enterprise.mattermost-license")
	licenseFile.WriteString(encoded)
	licenseFile.Close()
	fmt.Println("✅ License file saved: workspace-enterprise.mattermost-license")
	fmt.Println("")

	// ---- Second license: 500 users, 1 month ----
	oneMonthMs := int64(1000 * 60 * 60 * 24 * 30)

	license2 := &License{
		Id:        "workspace-starter-500-license",
		IssuedAt:  now,
		StartsAt:  now,
		ExpiresAt: now + oneMonthMs,
		Customer: &Customer{
			Id:      "workspace-customer-001",
			Name:    "marwan",
			Email:   "marwan@workspace.com",
			Company: "workspace",
		},
		Features: &Features{
			Users:                     intPtr(500),
			LDAP:                      boolPtr(true),
			LDAPGroups:                boolPtr(true),
			MFA:                       boolPtr(true),
			GoogleOAuth:               boolPtr(true),
			Office365OAuth:            boolPtr(true),
			OpenId:                    boolPtr(true),
			SAML:                      boolPtr(true),
			Compliance:                boolPtr(true),
			DataRetention:             boolPtr(true),
			MessageExport:             boolPtr(true),
			CustomPermissionsSchemes:  boolPtr(true),
			CustomTermsOfService:      boolPtr(true),
			Cluster:                   boolPtr(true),
			Metrics:                   boolPtr(true),
			Elasticsearch:             boolPtr(true),
			MHPNS:                     boolPtr(true),
			IDLoadedPushNotifications: boolPtr(true),
			EmailNotificationContents: boolPtr(true),
			Announcement:              boolPtr(true),
			AutoTranslation:           boolPtr(true),
			GuestAccounts:             boolPtr(true),
			GuestAccountsPermissions:  boolPtr(true),
			LockTeammateNameDisplay:   boolPtr(true),
			ThemeManagement:           boolPtr(true),
			EnterprisePlugins:         boolPtr(true),
			AdvancedLogging:           boolPtr(true),
			OutgoingOAuthConnections:  boolPtr(true),
			SharedChannels:            boolPtr(true),
			RemoteClusterService:      boolPtr(true),
			Cloud:                     boolPtr(false),
			FutureFeatures:            boolPtr(true),
		},
		SkuName:      "Workspace Enterprise Advanced",
		SkuShortName: "advanced",
		IsTrial:      false,
		IsGovSku:     false,
	}

	plaintext2, _ := json.Marshal(license2)
	h2 := sha512.New()
	h2.Write(plaintext2)
	sig2, _ := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA512, h2.Sum(nil))
	signed2 := append(plaintext2, sig2...)
	encoded2 := base64.StdEncoding.EncodeToString(signed2)

	licFile2, _ := os.Create("workspace-500users-1month.mattermost-license")
	licFile2.WriteString(encoded2)
	licFile2.Close()
	fmt.Println("✅ License file saved: workspace-500users-1month.mattermost-license")
	fmt.Println("   👤 Users: 500  |  ⏱ Duration: 1 month")

	// ---- Third license: 1 hour ----
	oneHourMs := int64(1000 * 60 * 60)

	license3 := &License{
		Id:        "workspace-1hour-trial-license",
		IssuedAt:  now,
		StartsAt:  now,
		ExpiresAt: now + oneHourMs,
		Customer: &Customer{
			Id:      "workspace-customer-001",
			Name:    "marwan",
			Email:   "marwan@workspace.com",
			Company: "workspace",
		},
		Features: &Features{
			Users:                     intPtr(1000000),
			LDAP:                      boolPtr(true),
			LDAPGroups:                boolPtr(true),
			MFA:                       boolPtr(true),
			GoogleOAuth:               boolPtr(true),
			Office365OAuth:            boolPtr(true),
			OpenId:                    boolPtr(true),
			SAML:                      boolPtr(true),
			Compliance:                boolPtr(true),
			DataRetention:             boolPtr(true),
			MessageExport:             boolPtr(true),
			CustomPermissionsSchemes:  boolPtr(true),
			CustomTermsOfService:      boolPtr(true),
			Cluster:                   boolPtr(true),
			Metrics:                   boolPtr(true),
			Elasticsearch:             boolPtr(true),
			MHPNS:                     boolPtr(true),
			IDLoadedPushNotifications: boolPtr(true),
			EmailNotificationContents: boolPtr(true),
			Announcement:              boolPtr(true),
			AutoTranslation:           boolPtr(true),
			GuestAccounts:             boolPtr(true),
			GuestAccountsPermissions:  boolPtr(true),
			LockTeammateNameDisplay:   boolPtr(true),
			ThemeManagement:           boolPtr(true),
			EnterprisePlugins:         boolPtr(true),
			AdvancedLogging:           boolPtr(true),
			OutgoingOAuthConnections:  boolPtr(true),
			SharedChannels:            boolPtr(true),
			RemoteClusterService:      boolPtr(true),
			Cloud:                     boolPtr(false),
			FutureFeatures:            boolPtr(true),
		},
		SkuName:      "Workspace Enterprise Advanced",
		SkuShortName: "advanced",
		IsTrial:      true,
		IsGovSku:     false,
	}

	plaintext3, _ := json.Marshal(license3)
	h3 := sha512.New()
	h3.Write(plaintext3)
	sig3, _ := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA512, h3.Sum(nil))
	signed3 := append(plaintext3, sig3...)
	encoded3 := base64.StdEncoding.EncodeToString(signed3)

	licFile3, _ := os.Create("workspace-1hour.mattermost-license")
	licFile3.WriteString(encoded3)
	licFile3.Close()
	fmt.Println("✅ License file saved: workspace-1hour.mattermost-license")
	fmt.Println("   ⏱ Duration: 1 hour")

	// ---- Fourth license: 1,000,000 users, 1 month ----
	license4 := &License{
		Id:        "workspace-1month-1M-license",
		IssuedAt:  now,
		StartsAt:  now,
		ExpiresAt: now + oneMonthMs,
		Customer: &Customer{
			Id:      "workspace-customer-001",
			Name:    "marwan",
			Email:   "marwan@workspace.com",
			Company: "workspace",
		},
		Features: &Features{
			Users:                     intPtr(1000000),
			LDAP:                      boolPtr(true),
			LDAPGroups:                boolPtr(true),
			MFA:                       boolPtr(true),
			GoogleOAuth:               boolPtr(true),
			Office365OAuth:            boolPtr(true),
			OpenId:                    boolPtr(true),
			SAML:                      boolPtr(true),
			Compliance:                boolPtr(true),
			DataRetention:             boolPtr(true),
			MessageExport:             boolPtr(true),
			CustomPermissionsSchemes:  boolPtr(true),
			CustomTermsOfService:      boolPtr(true),
			Cluster:                   boolPtr(true),
			Metrics:                   boolPtr(true),
			Elasticsearch:             boolPtr(true),
			MHPNS:                     boolPtr(true),
			IDLoadedPushNotifications: boolPtr(true),
			EmailNotificationContents: boolPtr(true),
			Announcement:              boolPtr(true),
			AutoTranslation:           boolPtr(true),
			GuestAccounts:             boolPtr(true),
			GuestAccountsPermissions:  boolPtr(true),
			LockTeammateNameDisplay:   boolPtr(true),
			ThemeManagement:           boolPtr(true),
			EnterprisePlugins:         boolPtr(true),
			AdvancedLogging:           boolPtr(true),
			OutgoingOAuthConnections:  boolPtr(true),
			SharedChannels:            boolPtr(true),
			RemoteClusterService:      boolPtr(true),
			Cloud:                     boolPtr(false),
			FutureFeatures:            boolPtr(true),
		},
		SkuName:      "Workspace Enterprise Advanced",
		SkuShortName: "advanced",
		IsTrial:      false,
		IsGovSku:     false,
	}

	plaintext4, _ := json.Marshal(license4)
	h4 := sha512.New()
	h4.Write(plaintext4)
	sig4, _ := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA512, h4.Sum(nil))
	signed4 := append(plaintext4, sig4...)
	encoded4 := base64.StdEncoding.EncodeToString(signed4)

	licFile4, _ := os.Create("workspace-1month-1M-users.mattermost-license")
	licFile4.WriteString(encoded4)
	licFile4.Close()
	fmt.Println("✅ License file saved: workspace-1month-1M-users.mattermost-license")
	fmt.Println("   👤 Users: 1,000,000  |  ⏱ Duration: 1 month")

	fmt.Println("")
	// ---- Fifth license: 2 users, 10 minutes (for testing expiration) ----
	tenMinutesMs := int64(1000 * 60 * 10)

	license5 := &License{
		Id:        "workspace-10min-test-license",
		IssuedAt:  now,
		StartsAt:  now,
		ExpiresAt: now + tenMinutesMs,
		Customer: &Customer{
			Id:      "workspace-customer-001",
			Name:    "marwan",
			Email:   "marwan@workspace.com",
			Company: "workspace",
		},
		Features: &Features{
			Users:                     intPtr(2),
			LDAP:                      boolPtr(true),
			LDAPGroups:                boolPtr(true),
			MFA:                       boolPtr(true),
			GoogleOAuth:               boolPtr(true),
			Office365OAuth:            boolPtr(true),
			OpenId:                    boolPtr(true),
			SAML:                      boolPtr(true),
			Compliance:                boolPtr(true),
			DataRetention:             boolPtr(true),
			MessageExport:             boolPtr(true),
			CustomPermissionsSchemes:  boolPtr(true),
			CustomTermsOfService:      boolPtr(true),
			Cluster:                   boolPtr(true),
			Metrics:                   boolPtr(true),
			Elasticsearch:             boolPtr(true),
			MHPNS:                     boolPtr(true),
			IDLoadedPushNotifications: boolPtr(true),
			EmailNotificationContents: boolPtr(true),
			Announcement:              boolPtr(true),
			AutoTranslation:           boolPtr(true),
			GuestAccounts:             boolPtr(true),
			GuestAccountsPermissions:  boolPtr(true),
			LockTeammateNameDisplay:   boolPtr(true),
			ThemeManagement:           boolPtr(true),
			EnterprisePlugins:         boolPtr(true),
			AdvancedLogging:           boolPtr(true),
			OutgoingOAuthConnections:  boolPtr(true),
			SharedChannels:            boolPtr(true),
			RemoteClusterService:      boolPtr(true),
			Cloud:                     boolPtr(false),
			FutureFeatures:            boolPtr(true),
		},
		SkuName:      "Workspace Enterprise Advanced",
		SkuShortName: "advanced",
		IsTrial:      true,
		IsGovSku:     false,
	}

	plaintext5, _ := json.Marshal(license5)
	h5 := sha512.New()
	h5.Write(plaintext5)
	sig5, _ := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA512, h5.Sum(nil))
	signed5 := append(plaintext5, sig5...)
	encoded5 := base64.StdEncoding.EncodeToString(signed5)

	licFile5, _ := os.Create("workspace-10min-2users.mattermost-license")
	licFile5.WriteString(encoded5)
	licFile5.Close()
	fmt.Println("✅ License file saved: workspace-10min-2users.mattermost-license")
	fmt.Println("   👤 Users: 2  |  ⏱ Duration: 10 minutes")

	fmt.Println("")
	// ---- Sixth license: 2 users, 2 days (for extended testing) ----
	twoDaysMs := int64(1000 * 60 * 60 * 24 * 2)

	license6 := &License{
		Id:        "workspace-2day-test-license",
		IssuedAt:  now,
		StartsAt:  now,
		ExpiresAt: now + twoDaysMs,
		Customer: &Customer{
			Id:      "workspace-customer-001",
			Name:    "marwan",
			Email:   "marwan@workspace.com",
			Company: "workspace",
		},
		Features: &Features{
			Users:                     intPtr(2),
			LDAP:                      boolPtr(true),
			LDAPGroups:                boolPtr(true),
			MFA:                       boolPtr(true),
			GoogleOAuth:               boolPtr(true),
			Office365OAuth:            boolPtr(true),
			OpenId:                    boolPtr(true),
			SAML:                      boolPtr(true),
			Compliance:                boolPtr(true),
			DataRetention:             boolPtr(true),
			MessageExport:             boolPtr(true),
			CustomPermissionsSchemes:  boolPtr(true),
			CustomTermsOfService:      boolPtr(true),
			Cluster:                   boolPtr(true),
			Metrics:                   boolPtr(true),
			Elasticsearch:             boolPtr(true),
			MHPNS:                     boolPtr(true),
			IDLoadedPushNotifications: boolPtr(true),
			EmailNotificationContents: boolPtr(true),
			Announcement:              boolPtr(true),
			AutoTranslation:           boolPtr(true),
			GuestAccounts:             boolPtr(true),
			GuestAccountsPermissions:  boolPtr(true),
			LockTeammateNameDisplay:   boolPtr(true),
			ThemeManagement:           boolPtr(true),
			EnterprisePlugins:         boolPtr(true),
			AdvancedLogging:           boolPtr(true),
			OutgoingOAuthConnections:  boolPtr(true),
			SharedChannels:            boolPtr(true),
			RemoteClusterService:      boolPtr(true),
			Cloud:                     boolPtr(false),
			FutureFeatures:            boolPtr(true),
		},
		SkuName:      "Workspace Enterprise Advanced",
		SkuShortName: "advanced",
		IsTrial:      true,
		IsGovSku:     false,
	}

	plaintext6, _ := json.Marshal(license6)
	h6 := sha512.New()
	h6.Write(plaintext6)
	sig6, _ := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA512, h6.Sum(nil))
	signed6 := append(plaintext6, sig6...)
	encoded6 := base64.StdEncoding.EncodeToString(signed6)

	licFile6, _ := os.Create("workspace-2days-2users.mattermost-license")
	licFile6.WriteString(encoded6)
	licFile6.Close()
	fmt.Println("✅ License file saved: workspace-2days-2users.mattermost-license")
	fmt.Println("   👤 Users: 2  |  ⏱ Duration: 2 days")

	fmt.Println("")
	fmt.Println("📋 Next step: upload this file to the Admin Console.")
}
