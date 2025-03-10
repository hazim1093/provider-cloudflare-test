// SPDX-FileCopyrightText: 2024 The Crossplane Authors <https://crossplane.io>
//
// SPDX-License-Identifier: Apache-2.0

// Code generated by upjet. DO NOT EDIT.

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

	v1 "github.com/crossplane/crossplane-runtime/apis/common/v1"
)

type InputInitParameters struct {

	// (Number) The Number of active threats.
	// The Number of active threats.
	ActiveThreats *float64 `json:"activeThreats,omitempty" tf:"active_threats,omitempty"`

	// (String) UUID of Cloudflare managed certificate.
	// UUID of Cloudflare managed certificate.
	CertificateID *string `json:"certificateId,omitempty" tf:"certificate_id,omitempty"`

	// (List of String) List of volume names to be checked for encryption.
	// List of volume names to be checked for encryption.
	CheckDisks []*string `json:"checkDisks,omitempty" tf:"check_disks,omitempty"`

	// (Boolean) Confirm the certificate was not imported from another device. We recommend keeping this enabled unless the certificate was deployed without a private key.
	// Confirm the certificate was not imported from another device. We recommend keeping this enabled unless the certificate was deployed without a private key.
	CheckPrivateKey *bool `json:"checkPrivateKey,omitempty" tf:"check_private_key,omitempty"`

	// (String) Common Name that is protected by the certificate
	// Common Name that is protected by the certificate
	Cn *string `json:"cn,omitempty" tf:"cn,omitempty"`

	// (String) Compliance Status
	// Compliance Status
	ComplianceStatus *string `json:"complianceStatus,omitempty" tf:"compliance_status,omitempty"`

	// (String) Posture Integration ID.
	// Posture Integration ID.
	ConnectionID *string `json:"connectionId,omitempty" tf:"connection_id,omitempty"`

	// (String) Count Operator
	// Count Operator
	CountOperator *string `json:"countOperator,omitempty" tf:"count_operator,omitempty"`

	// (String) Domain
	// Domain
	Domain *string `json:"domain,omitempty" tf:"domain,omitempty"`

	// (String) For more details on eid last seen, refer to the Tanium documentation.
	// For more details on eid last seen, refer to the Tanium documentation.
	EidLastSeen *string `json:"eidLastSeen,omitempty" tf:"eid_last_seen,omitempty"`

	// (Boolean) Enabled
	// Enabled
	Enabled *bool `json:"enabled,omitempty" tf:"enabled,omitempty"`

	// (Boolean) Whether or not file exists
	// Whether or not file exists
	Exists *bool `json:"exists,omitempty" tf:"exists,omitempty"`

	// (List of String) List of values indicating purposes for which the certificate public key can be used
	// List of values indicating purposes for which the certificate public key can be used
	ExtendedKeyUsage []*string `json:"extendedKeyUsage,omitempty" tf:"extended_key_usage,omitempty"`

	// (String) API UUID.
	// List ID.
	ID *string `json:"id,omitempty" tf:"id,omitempty"`

	// (Boolean) Whether device is infected.
	// Whether device is infected.
	Infected *bool `json:"infected,omitempty" tf:"infected,omitempty"`

	// (Boolean) Whether device is active.
	// Whether device is active.
	IsActive *bool `json:"isActive,omitempty" tf:"is_active,omitempty"`

	// (String) The Number of Issues.
	// The Number of Issues.
	IssueCount *string `json:"issueCount,omitempty" tf:"issue_count,omitempty"`

	// (String) For more details on last seen, please refer to the Crowdstrike documentation.
	// For more details on last seen, please refer to the Crowdstrike documentation.
	LastSeen *string `json:"lastSeen,omitempty" tf:"last_seen,omitempty"`

	// (Attributes) (see below for nested schema)
	Locations *LocationsInitParameters `json:"locations,omitempty" tf:"locations,omitempty"`

	// (String) Network status of device.
	// Network status of device.
	NetworkStatus *string `json:"networkStatus,omitempty" tf:"network_status,omitempty"`

	// (String) Operating system
	// Operating system
	OperatingSystem *string `json:"operatingSystem,omitempty" tf:"operating_system,omitempty"`

	// (String) Agent operational state.
	// Agent operational state.
	OperationalState *string `json:"operationalState,omitempty" tf:"operational_state,omitempty"`

	// (String) operator
	// operator
	Operator *string `json:"operator,omitempty" tf:"operator,omitempty"`

	// (String) Os Version
	// Os Version
	Os *string `json:"os,omitempty" tf:"os,omitempty"`

	// (String) Operating System Distribution Name (linux only)
	// Operating System Distribution Name (linux only)
	OsDistroName *string `json:"osDistroName,omitempty" tf:"os_distro_name,omitempty"`

	// (String) Version of OS Distribution (linux only)
	// Version of OS Distribution (linux only)
	OsDistroRevision *string `json:"osDistroRevision,omitempty" tf:"os_distro_revision,omitempty"`

	// (String) Additional version data. For Mac or iOS, the Product Version Extra. For Linux, the kernel release version. (Mac, iOS, and Linux only)
	// Additional version data. For Mac or iOS, the Product Version Extra. For Linux, the kernel release version. (Mac, iOS, and Linux only)
	OsVersionExtra *string `json:"osVersionExtra,omitempty" tf:"os_version_extra,omitempty"`

	// (String) overall
	// overall
	Overall *string `json:"overall,omitempty" tf:"overall,omitempty"`

	// (String) File path.
	// File path.
	Path *string `json:"path,omitempty" tf:"path,omitempty"`

	// (Boolean) Whether to check all disks for encryption.
	// Whether to check all disks for encryption.
	RequireAll *bool `json:"requireAll,omitempty" tf:"require_all,omitempty"`

	// (String) For more details on risk level, refer to the Tanium documentation.
	// For more details on risk level, refer to the Tanium documentation.
	RiskLevel *string `json:"riskLevel,omitempty" tf:"risk_level,omitempty"`

	// 100 assigned to devices set by the 3rd party posture provider.
	// A value between 0-100 assigned to devices set by the 3rd party posture provider.
	Score *float64 `json:"score,omitempty" tf:"score,omitempty"`

	// (String) Score Operator
	// Score Operator
	ScoreOperator *string `json:"scoreOperator,omitempty" tf:"score_operator,omitempty"`

	// (String) SensorConfig
	// SensorConfig
	SensorConfig *string `json:"sensorConfig,omitempty" tf:"sensor_config,omitempty"`

	// 256.
	// SHA-256.
	Sha256 *string `json:"sha256,omitempty" tf:"sha256,omitempty"`

	// (String) For more details on state, please refer to the Crowdstrike documentation.
	// For more details on state, please refer to the Crowdstrike documentation.
	State *string `json:"state,omitempty" tf:"state,omitempty"`

	// (String) Signing certificate thumbprint.
	// Signing certificate thumbprint.
	Thumbprint *string `json:"thumbprint,omitempty" tf:"thumbprint,omitempty"`

	// (Number) For more details on total score, refer to the Tanium documentation.
	// For more details on total score, refer to the Tanium documentation.
	TotalScore *float64 `json:"totalScore,omitempty" tf:"total_score,omitempty"`

	// (String) Version of OS
	// Version of OS
	Version *string `json:"version,omitempty" tf:"version,omitempty"`

	// (String) Version Operator
	// Version Operator
	VersionOperator *string `json:"versionOperator,omitempty" tf:"version_operator,omitempty"`
}

type InputObservation struct {

	// (Number) The Number of active threats.
	// The Number of active threats.
	ActiveThreats *float64 `json:"activeThreats,omitempty" tf:"active_threats,omitempty"`

	// (String) UUID of Cloudflare managed certificate.
	// UUID of Cloudflare managed certificate.
	CertificateID *string `json:"certificateId,omitempty" tf:"certificate_id,omitempty"`

	// (List of String) List of volume names to be checked for encryption.
	// List of volume names to be checked for encryption.
	CheckDisks []*string `json:"checkDisks,omitempty" tf:"check_disks,omitempty"`

	// (Boolean) Confirm the certificate was not imported from another device. We recommend keeping this enabled unless the certificate was deployed without a private key.
	// Confirm the certificate was not imported from another device. We recommend keeping this enabled unless the certificate was deployed without a private key.
	CheckPrivateKey *bool `json:"checkPrivateKey,omitempty" tf:"check_private_key,omitempty"`

	// (String) Common Name that is protected by the certificate
	// Common Name that is protected by the certificate
	Cn *string `json:"cn,omitempty" tf:"cn,omitempty"`

	// (String) Compliance Status
	// Compliance Status
	ComplianceStatus *string `json:"complianceStatus,omitempty" tf:"compliance_status,omitempty"`

	// (String) Posture Integration ID.
	// Posture Integration ID.
	ConnectionID *string `json:"connectionId,omitempty" tf:"connection_id,omitempty"`

	// (String) Count Operator
	// Count Operator
	CountOperator *string `json:"countOperator,omitempty" tf:"count_operator,omitempty"`

	// (String) Domain
	// Domain
	Domain *string `json:"domain,omitempty" tf:"domain,omitempty"`

	// (String) For more details on eid last seen, refer to the Tanium documentation.
	// For more details on eid last seen, refer to the Tanium documentation.
	EidLastSeen *string `json:"eidLastSeen,omitempty" tf:"eid_last_seen,omitempty"`

	// (Boolean) Enabled
	// Enabled
	Enabled *bool `json:"enabled,omitempty" tf:"enabled,omitempty"`

	// (Boolean) Whether or not file exists
	// Whether or not file exists
	Exists *bool `json:"exists,omitempty" tf:"exists,omitempty"`

	// (List of String) List of values indicating purposes for which the certificate public key can be used
	// List of values indicating purposes for which the certificate public key can be used
	ExtendedKeyUsage []*string `json:"extendedKeyUsage,omitempty" tf:"extended_key_usage,omitempty"`

	// (String) API UUID.
	// List ID.
	ID *string `json:"id,omitempty" tf:"id,omitempty"`

	// (Boolean) Whether device is infected.
	// Whether device is infected.
	Infected *bool `json:"infected,omitempty" tf:"infected,omitempty"`

	// (Boolean) Whether device is active.
	// Whether device is active.
	IsActive *bool `json:"isActive,omitempty" tf:"is_active,omitempty"`

	// (String) The Number of Issues.
	// The Number of Issues.
	IssueCount *string `json:"issueCount,omitempty" tf:"issue_count,omitempty"`

	// (String) For more details on last seen, please refer to the Crowdstrike documentation.
	// For more details on last seen, please refer to the Crowdstrike documentation.
	LastSeen *string `json:"lastSeen,omitempty" tf:"last_seen,omitempty"`

	// (Attributes) (see below for nested schema)
	Locations *LocationsObservation `json:"locations,omitempty" tf:"locations,omitempty"`

	// (String) Network status of device.
	// Network status of device.
	NetworkStatus *string `json:"networkStatus,omitempty" tf:"network_status,omitempty"`

	// (String) Operating system
	// Operating system
	OperatingSystem *string `json:"operatingSystem,omitempty" tf:"operating_system,omitempty"`

	// (String) Agent operational state.
	// Agent operational state.
	OperationalState *string `json:"operationalState,omitempty" tf:"operational_state,omitempty"`

	// (String) operator
	// operator
	Operator *string `json:"operator,omitempty" tf:"operator,omitempty"`

	// (String) Os Version
	// Os Version
	Os *string `json:"os,omitempty" tf:"os,omitempty"`

	// (String) Operating System Distribution Name (linux only)
	// Operating System Distribution Name (linux only)
	OsDistroName *string `json:"osDistroName,omitempty" tf:"os_distro_name,omitempty"`

	// (String) Version of OS Distribution (linux only)
	// Version of OS Distribution (linux only)
	OsDistroRevision *string `json:"osDistroRevision,omitempty" tf:"os_distro_revision,omitempty"`

	// (String) Additional version data. For Mac or iOS, the Product Version Extra. For Linux, the kernel release version. (Mac, iOS, and Linux only)
	// Additional version data. For Mac or iOS, the Product Version Extra. For Linux, the kernel release version. (Mac, iOS, and Linux only)
	OsVersionExtra *string `json:"osVersionExtra,omitempty" tf:"os_version_extra,omitempty"`

	// (String) overall
	// overall
	Overall *string `json:"overall,omitempty" tf:"overall,omitempty"`

	// (String) File path.
	// File path.
	Path *string `json:"path,omitempty" tf:"path,omitempty"`

	// (Boolean) Whether to check all disks for encryption.
	// Whether to check all disks for encryption.
	RequireAll *bool `json:"requireAll,omitempty" tf:"require_all,omitempty"`

	// (String) For more details on risk level, refer to the Tanium documentation.
	// For more details on risk level, refer to the Tanium documentation.
	RiskLevel *string `json:"riskLevel,omitempty" tf:"risk_level,omitempty"`

	// 100 assigned to devices set by the 3rd party posture provider.
	// A value between 0-100 assigned to devices set by the 3rd party posture provider.
	Score *float64 `json:"score,omitempty" tf:"score,omitempty"`

	// (String) Score Operator
	// Score Operator
	ScoreOperator *string `json:"scoreOperator,omitempty" tf:"score_operator,omitempty"`

	// (String) SensorConfig
	// SensorConfig
	SensorConfig *string `json:"sensorConfig,omitempty" tf:"sensor_config,omitempty"`

	// 256.
	// SHA-256.
	Sha256 *string `json:"sha256,omitempty" tf:"sha256,omitempty"`

	// (String) For more details on state, please refer to the Crowdstrike documentation.
	// For more details on state, please refer to the Crowdstrike documentation.
	State *string `json:"state,omitempty" tf:"state,omitempty"`

	// (String) Signing certificate thumbprint.
	// Signing certificate thumbprint.
	Thumbprint *string `json:"thumbprint,omitempty" tf:"thumbprint,omitempty"`

	// (Number) For more details on total score, refer to the Tanium documentation.
	// For more details on total score, refer to the Tanium documentation.
	TotalScore *float64 `json:"totalScore,omitempty" tf:"total_score,omitempty"`

	// (String) Version of OS
	// Version of OS
	Version *string `json:"version,omitempty" tf:"version,omitempty"`

	// (String) Version Operator
	// Version Operator
	VersionOperator *string `json:"versionOperator,omitempty" tf:"version_operator,omitempty"`
}

type InputParameters struct {

	// (Number) The Number of active threats.
	// The Number of active threats.
	// +kubebuilder:validation:Optional
	ActiveThreats *float64 `json:"activeThreats,omitempty" tf:"active_threats,omitempty"`

	// (String) UUID of Cloudflare managed certificate.
	// UUID of Cloudflare managed certificate.
	// +kubebuilder:validation:Optional
	CertificateID *string `json:"certificateId,omitempty" tf:"certificate_id,omitempty"`

	// (List of String) List of volume names to be checked for encryption.
	// List of volume names to be checked for encryption.
	// +kubebuilder:validation:Optional
	CheckDisks []*string `json:"checkDisks,omitempty" tf:"check_disks,omitempty"`

	// (Boolean) Confirm the certificate was not imported from another device. We recommend keeping this enabled unless the certificate was deployed without a private key.
	// Confirm the certificate was not imported from another device. We recommend keeping this enabled unless the certificate was deployed without a private key.
	// +kubebuilder:validation:Optional
	CheckPrivateKey *bool `json:"checkPrivateKey,omitempty" tf:"check_private_key,omitempty"`

	// (String) Common Name that is protected by the certificate
	// Common Name that is protected by the certificate
	// +kubebuilder:validation:Optional
	Cn *string `json:"cn,omitempty" tf:"cn,omitempty"`

	// (String) Compliance Status
	// Compliance Status
	// +kubebuilder:validation:Optional
	ComplianceStatus *string `json:"complianceStatus,omitempty" tf:"compliance_status,omitempty"`

	// (String) Posture Integration ID.
	// Posture Integration ID.
	// +kubebuilder:validation:Optional
	ConnectionID *string `json:"connectionId,omitempty" tf:"connection_id,omitempty"`

	// (String) Count Operator
	// Count Operator
	// +kubebuilder:validation:Optional
	CountOperator *string `json:"countOperator,omitempty" tf:"count_operator,omitempty"`

	// (String) Domain
	// Domain
	// +kubebuilder:validation:Optional
	Domain *string `json:"domain,omitempty" tf:"domain,omitempty"`

	// (String) For more details on eid last seen, refer to the Tanium documentation.
	// For more details on eid last seen, refer to the Tanium documentation.
	// +kubebuilder:validation:Optional
	EidLastSeen *string `json:"eidLastSeen,omitempty" tf:"eid_last_seen,omitempty"`

	// (Boolean) Enabled
	// Enabled
	// +kubebuilder:validation:Optional
	Enabled *bool `json:"enabled,omitempty" tf:"enabled,omitempty"`

	// (Boolean) Whether or not file exists
	// Whether or not file exists
	// +kubebuilder:validation:Optional
	Exists *bool `json:"exists,omitempty" tf:"exists,omitempty"`

	// (List of String) List of values indicating purposes for which the certificate public key can be used
	// List of values indicating purposes for which the certificate public key can be used
	// +kubebuilder:validation:Optional
	ExtendedKeyUsage []*string `json:"extendedKeyUsage,omitempty" tf:"extended_key_usage,omitempty"`

	// (String) API UUID.
	// List ID.
	// +kubebuilder:validation:Optional
	ID *string `json:"id,omitempty" tf:"id,omitempty"`

	// (Boolean) Whether device is infected.
	// Whether device is infected.
	// +kubebuilder:validation:Optional
	Infected *bool `json:"infected,omitempty" tf:"infected,omitempty"`

	// (Boolean) Whether device is active.
	// Whether device is active.
	// +kubebuilder:validation:Optional
	IsActive *bool `json:"isActive,omitempty" tf:"is_active,omitempty"`

	// (String) The Number of Issues.
	// The Number of Issues.
	// +kubebuilder:validation:Optional
	IssueCount *string `json:"issueCount,omitempty" tf:"issue_count,omitempty"`

	// (String) For more details on last seen, please refer to the Crowdstrike documentation.
	// For more details on last seen, please refer to the Crowdstrike documentation.
	// +kubebuilder:validation:Optional
	LastSeen *string `json:"lastSeen,omitempty" tf:"last_seen,omitempty"`

	// (Attributes) (see below for nested schema)
	// +kubebuilder:validation:Optional
	Locations *LocationsParameters `json:"locations,omitempty" tf:"locations,omitempty"`

	// (String) Network status of device.
	// Network status of device.
	// +kubebuilder:validation:Optional
	NetworkStatus *string `json:"networkStatus,omitempty" tf:"network_status,omitempty"`

	// (String) Operating system
	// Operating system
	// +kubebuilder:validation:Optional
	OperatingSystem *string `json:"operatingSystem,omitempty" tf:"operating_system,omitempty"`

	// (String) Agent operational state.
	// Agent operational state.
	// +kubebuilder:validation:Optional
	OperationalState *string `json:"operationalState,omitempty" tf:"operational_state,omitempty"`

	// (String) operator
	// operator
	// +kubebuilder:validation:Optional
	Operator *string `json:"operator,omitempty" tf:"operator,omitempty"`

	// (String) Os Version
	// Os Version
	// +kubebuilder:validation:Optional
	Os *string `json:"os,omitempty" tf:"os,omitempty"`

	// (String) Operating System Distribution Name (linux only)
	// Operating System Distribution Name (linux only)
	// +kubebuilder:validation:Optional
	OsDistroName *string `json:"osDistroName,omitempty" tf:"os_distro_name,omitempty"`

	// (String) Version of OS Distribution (linux only)
	// Version of OS Distribution (linux only)
	// +kubebuilder:validation:Optional
	OsDistroRevision *string `json:"osDistroRevision,omitempty" tf:"os_distro_revision,omitempty"`

	// (String) Additional version data. For Mac or iOS, the Product Version Extra. For Linux, the kernel release version. (Mac, iOS, and Linux only)
	// Additional version data. For Mac or iOS, the Product Version Extra. For Linux, the kernel release version. (Mac, iOS, and Linux only)
	// +kubebuilder:validation:Optional
	OsVersionExtra *string `json:"osVersionExtra,omitempty" tf:"os_version_extra,omitempty"`

	// (String) overall
	// overall
	// +kubebuilder:validation:Optional
	Overall *string `json:"overall,omitempty" tf:"overall,omitempty"`

	// (String) File path.
	// File path.
	// +kubebuilder:validation:Optional
	Path *string `json:"path,omitempty" tf:"path,omitempty"`

	// (Boolean) Whether to check all disks for encryption.
	// Whether to check all disks for encryption.
	// +kubebuilder:validation:Optional
	RequireAll *bool `json:"requireAll,omitempty" tf:"require_all,omitempty"`

	// (String) For more details on risk level, refer to the Tanium documentation.
	// For more details on risk level, refer to the Tanium documentation.
	// +kubebuilder:validation:Optional
	RiskLevel *string `json:"riskLevel,omitempty" tf:"risk_level,omitempty"`

	// 100 assigned to devices set by the 3rd party posture provider.
	// A value between 0-100 assigned to devices set by the 3rd party posture provider.
	// +kubebuilder:validation:Optional
	Score *float64 `json:"score,omitempty" tf:"score,omitempty"`

	// (String) Score Operator
	// Score Operator
	// +kubebuilder:validation:Optional
	ScoreOperator *string `json:"scoreOperator,omitempty" tf:"score_operator,omitempty"`

	// (String) SensorConfig
	// SensorConfig
	// +kubebuilder:validation:Optional
	SensorConfig *string `json:"sensorConfig,omitempty" tf:"sensor_config,omitempty"`

	// 256.
	// SHA-256.
	// +kubebuilder:validation:Optional
	Sha256 *string `json:"sha256,omitempty" tf:"sha256,omitempty"`

	// (String) For more details on state, please refer to the Crowdstrike documentation.
	// For more details on state, please refer to the Crowdstrike documentation.
	// +kubebuilder:validation:Optional
	State *string `json:"state,omitempty" tf:"state,omitempty"`

	// (String) Signing certificate thumbprint.
	// Signing certificate thumbprint.
	// +kubebuilder:validation:Optional
	Thumbprint *string `json:"thumbprint,omitempty" tf:"thumbprint,omitempty"`

	// (Number) For more details on total score, refer to the Tanium documentation.
	// For more details on total score, refer to the Tanium documentation.
	// +kubebuilder:validation:Optional
	TotalScore *float64 `json:"totalScore,omitempty" tf:"total_score,omitempty"`

	// (String) Version of OS
	// Version of OS
	// +kubebuilder:validation:Optional
	Version *string `json:"version,omitempty" tf:"version,omitempty"`

	// (String) Version Operator
	// Version Operator
	// +kubebuilder:validation:Optional
	VersionOperator *string `json:"versionOperator,omitempty" tf:"version_operator,omitempty"`
}

type LocationsInitParameters struct {

	// (List of String) List of paths to check for client certificate on linux.
	// List of paths to check for client certificate on linux.
	Paths []*string `json:"paths,omitempty" tf:"paths,omitempty"`

	// (List of String) List of trust stores to check for client certificate.
	// List of trust stores to check for client certificate.
	TrustStores []*string `json:"trustStores,omitempty" tf:"trust_stores,omitempty"`
}

type LocationsObservation struct {

	// (List of String) List of paths to check for client certificate on linux.
	// List of paths to check for client certificate on linux.
	Paths []*string `json:"paths,omitempty" tf:"paths,omitempty"`

	// (List of String) List of trust stores to check for client certificate.
	// List of trust stores to check for client certificate.
	TrustStores []*string `json:"trustStores,omitempty" tf:"trust_stores,omitempty"`
}

type LocationsParameters struct {

	// (List of String) List of paths to check for client certificate on linux.
	// List of paths to check for client certificate on linux.
	// +kubebuilder:validation:Optional
	Paths []*string `json:"paths,omitempty" tf:"paths,omitempty"`

	// (List of String) List of trust stores to check for client certificate.
	// List of trust stores to check for client certificate.
	// +kubebuilder:validation:Optional
	TrustStores []*string `json:"trustStores,omitempty" tf:"trust_stores,omitempty"`
}

type MatchInitParameters struct {

	// (String)
	Platform *string `json:"platform,omitempty" tf:"platform,omitempty"`
}

type MatchObservation struct {

	// (String)
	Platform *string `json:"platform,omitempty" tf:"platform,omitempty"`
}

type MatchParameters struct {

	// (String)
	// +kubebuilder:validation:Optional
	Platform *string `json:"platform,omitempty" tf:"platform,omitempty"`
}

type TrustDevicePostureRuleInitParameters struct {

	// (String)
	AccountID *string `json:"accountId,omitempty" tf:"account_id,omitempty"`

	// (String) The description of the device posture rule.
	// The description of the device posture rule.
	Description *string `json:"description,omitempty" tf:"description,omitempty"`

	// (String) Sets the expiration time for a posture check result. If empty, the result remains valid until it is overwritten by new data from the WARP client.
	// Sets the expiration time for a posture check result. If empty, the result remains valid until it is overwritten by new data from the WARP client.
	Expiration *string `json:"expiration,omitempty" tf:"expiration,omitempty"`

	// (Attributes) The value to be checked against. (see below for nested schema)
	Input *InputInitParameters `json:"input,omitempty" tf:"input,omitempty"`

	// (Attributes List) The conditions that the client must match to run the rule. (see below for nested schema)
	Match []MatchInitParameters `json:"match,omitempty" tf:"match,omitempty"`

	// (String) Polling frequency for the WARP client posture check. Default: 5m (poll every five minutes). Minimum: 1m.
	// Polling frequency for the WARP client posture check. Default: `5m` (poll every five minutes). Minimum: `1m`.
	Schedule *string `json:"schedule,omitempty" tf:"schedule,omitempty"`

	// (String) The type of device posture rule.
	// The type of device posture rule.
	Type *string `json:"type,omitempty" tf:"type,omitempty"`
}

type TrustDevicePostureRuleObservation struct {

	// (String)
	AccountID *string `json:"accountId,omitempty" tf:"account_id,omitempty"`

	// (String) The description of the device posture rule.
	// The description of the device posture rule.
	Description *string `json:"description,omitempty" tf:"description,omitempty"`

	// (String) Sets the expiration time for a posture check result. If empty, the result remains valid until it is overwritten by new data from the WARP client.
	// Sets the expiration time for a posture check result. If empty, the result remains valid until it is overwritten by new data from the WARP client.
	Expiration *string `json:"expiration,omitempty" tf:"expiration,omitempty"`

	// (String) API UUID.
	ID *string `json:"id,omitempty" tf:"id,omitempty"`

	// (Attributes) The value to be checked against. (see below for nested schema)
	Input *InputObservation `json:"input,omitempty" tf:"input,omitempty"`

	// (Attributes List) The conditions that the client must match to run the rule. (see below for nested schema)
	Match []MatchObservation `json:"match,omitempty" tf:"match,omitempty"`

	// (String) Polling frequency for the WARP client posture check. Default: 5m (poll every five minutes). Minimum: 1m.
	// Polling frequency for the WARP client posture check. Default: `5m` (poll every five minutes). Minimum: `1m`.
	Schedule *string `json:"schedule,omitempty" tf:"schedule,omitempty"`

	// (String) The type of device posture rule.
	// The type of device posture rule.
	Type *string `json:"type,omitempty" tf:"type,omitempty"`
}

type TrustDevicePostureRuleParameters struct {

	// (String)
	// +kubebuilder:validation:Optional
	AccountID *string `json:"accountId,omitempty" tf:"account_id,omitempty"`

	// (String) The description of the device posture rule.
	// The description of the device posture rule.
	// +kubebuilder:validation:Optional
	Description *string `json:"description,omitempty" tf:"description,omitempty"`

	// (String) Sets the expiration time for a posture check result. If empty, the result remains valid until it is overwritten by new data from the WARP client.
	// Sets the expiration time for a posture check result. If empty, the result remains valid until it is overwritten by new data from the WARP client.
	// +kubebuilder:validation:Optional
	Expiration *string `json:"expiration,omitempty" tf:"expiration,omitempty"`

	// (Attributes) The value to be checked against. (see below for nested schema)
	// +kubebuilder:validation:Optional
	Input *InputParameters `json:"input,omitempty" tf:"input,omitempty"`

	// (Attributes List) The conditions that the client must match to run the rule. (see below for nested schema)
	// +kubebuilder:validation:Optional
	Match []MatchParameters `json:"match,omitempty" tf:"match,omitempty"`

	// (String) Polling frequency for the WARP client posture check. Default: 5m (poll every five minutes). Minimum: 1m.
	// Polling frequency for the WARP client posture check. Default: `5m` (poll every five minutes). Minimum: `1m`.
	// +kubebuilder:validation:Optional
	Schedule *string `json:"schedule,omitempty" tf:"schedule,omitempty"`

	// (String) The type of device posture rule.
	// The type of device posture rule.
	// +kubebuilder:validation:Optional
	Type *string `json:"type,omitempty" tf:"type,omitempty"`
}

// TrustDevicePostureRuleSpec defines the desired state of TrustDevicePostureRule
type TrustDevicePostureRuleSpec struct {
	v1.ResourceSpec `json:",inline"`
	ForProvider     TrustDevicePostureRuleParameters `json:"forProvider"`
	// THIS IS A BETA FIELD. It will be honored
	// unless the Management Policies feature flag is disabled.
	// InitProvider holds the same fields as ForProvider, with the exception
	// of Identifier and other resource reference fields. The fields that are
	// in InitProvider are merged into ForProvider when the resource is created.
	// The same fields are also added to the terraform ignore_changes hook, to
	// avoid updating them after creation. This is useful for fields that are
	// required on creation, but we do not desire to update them after creation,
	// for example because of an external controller is managing them, like an
	// autoscaler.
	InitProvider TrustDevicePostureRuleInitParameters `json:"initProvider,omitempty"`
}

// TrustDevicePostureRuleStatus defines the observed state of TrustDevicePostureRule.
type TrustDevicePostureRuleStatus struct {
	v1.ResourceStatus `json:",inline"`
	AtProvider        TrustDevicePostureRuleObservation `json:"atProvider,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:storageversion

// TrustDevicePostureRule is the Schema for the TrustDevicePostureRules API.
// +kubebuilder:printcolumn:name="SYNCED",type="string",JSONPath=".status.conditions[?(@.type=='Synced')].status"
// +kubebuilder:printcolumn:name="READY",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="EXTERNAL-NAME",type="string",JSONPath=".metadata.annotations.crossplane\\.io/external-name"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:resource:scope=Cluster,categories={crossplane,managed,cloudflare}
type TrustDevicePostureRule struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.accountId) || (has(self.initProvider) && has(self.initProvider.accountId))",message="spec.forProvider.accountId is a required parameter"
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.match) || (has(self.initProvider) && has(self.initProvider.match))",message="spec.forProvider.match is a required parameter"
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.type) || (has(self.initProvider) && has(self.initProvider.type))",message="spec.forProvider.type is a required parameter"
	Spec   TrustDevicePostureRuleSpec   `json:"spec"`
	Status TrustDevicePostureRuleStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// TrustDevicePostureRuleList contains a list of TrustDevicePostureRules
type TrustDevicePostureRuleList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []TrustDevicePostureRule `json:"items"`
}

// Repository type metadata.
var (
	TrustDevicePostureRule_Kind             = "TrustDevicePostureRule"
	TrustDevicePostureRule_GroupKind        = schema.GroupKind{Group: CRDGroup, Kind: TrustDevicePostureRule_Kind}.String()
	TrustDevicePostureRule_KindAPIVersion   = TrustDevicePostureRule_Kind + "." + CRDGroupVersion.String()
	TrustDevicePostureRule_GroupVersionKind = CRDGroupVersion.WithKind(TrustDevicePostureRule_Kind)
)

func init() {
	SchemeBuilder.Register(&TrustDevicePostureRule{}, &TrustDevicePostureRuleList{})
}
