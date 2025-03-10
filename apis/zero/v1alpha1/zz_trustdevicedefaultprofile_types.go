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

type TrustDeviceDefaultProfileExcludeInitParameters struct {
}

type TrustDeviceDefaultProfileExcludeObservation struct {

	// (String) The address in CIDR format to exclude from the tunnel. If address is present, host must not be present.
	// The address in CIDR format to exclude from the tunnel. If `address` is present, `host` must not be present.
	Address *string `json:"address,omitempty" tf:"address,omitempty"`

	// (String) A description of the Split Tunnel item, displayed in the client UI.
	// A description of the Split Tunnel item, displayed in the client UI.
	Description *string `json:"description,omitempty" tf:"description,omitempty"`

	// (String) The domain name to exclude from the tunnel. If host is present, address must not be present.
	// The domain name to exclude from the tunnel. If `host` is present, `address` must not be present.
	Host *string `json:"host,omitempty" tf:"host,omitempty"`
}

type TrustDeviceDefaultProfileExcludeParameters struct {
}

type TrustDeviceDefaultProfileFallbackDomainsInitParameters struct {
}

type TrustDeviceDefaultProfileFallbackDomainsObservation struct {

	// (List of String) A list of IP addresses to handle domain resolution.
	// A list of IP addresses to handle domain resolution.
	DNSServer []*string `json:"dnsServer,omitempty" tf:"dns_server,omitempty"`

	// (String) A description of the Split Tunnel item, displayed in the client UI.
	// A description of the fallback domain, displayed in the client UI.
	Description *string `json:"description,omitempty" tf:"description,omitempty"`

	// (String) The domain suffix to match when resolving locally.
	// The domain suffix to match when resolving locally.
	Suffix *string `json:"suffix,omitempty" tf:"suffix,omitempty"`
}

type TrustDeviceDefaultProfileFallbackDomainsParameters struct {
}

type TrustDeviceDefaultProfileIncludeInitParameters struct {
}

type TrustDeviceDefaultProfileIncludeObservation struct {

	// (String) The address in CIDR format to exclude from the tunnel. If address is present, host must not be present.
	// The address in CIDR format to include in the tunnel. If address is present, host must not be present.
	Address *string `json:"address,omitempty" tf:"address,omitempty"`

	// (String) A description of the Split Tunnel item, displayed in the client UI.
	// A description of the split tunnel item, displayed in the client UI.
	Description *string `json:"description,omitempty" tf:"description,omitempty"`

	// (String) The domain name to exclude from the tunnel. If host is present, address must not be present.
	// The domain name to include in the tunnel. If host is present, address must not be present.
	Host *string `json:"host,omitempty" tf:"host,omitempty"`
}

type TrustDeviceDefaultProfileIncludeParameters struct {
}

type TrustDeviceDefaultProfileInitParameters struct {

	// (String)
	AccountID *string `json:"accountId,omitempty" tf:"account_id,omitempty"`

	// (Boolean) Whether to allow the user to switch WARP between modes.
	// Whether to allow the user to switch WARP between modes.
	AllowModeSwitch *bool `json:"allowModeSwitch,omitempty" tf:"allow_mode_switch,omitempty"`

	// (Boolean) Whether to receive update notifications when a new version of the client is available.
	// Whether to receive update notifications when a new version of the client is available.
	AllowUpdates *bool `json:"allowUpdates,omitempty" tf:"allow_updates,omitempty"`

	// (Boolean) Whether to allow devices to leave the organization.
	// Whether to allow devices to leave the organization.
	AllowedToLeave *bool `json:"allowedToLeave,omitempty" tf:"allowed_to_leave,omitempty"`

	// (Number) The amount of time in seconds to reconnect after having been disabled.
	// The amount of time in seconds to reconnect after having been disabled.
	AutoConnect *float64 `json:"autoConnect,omitempty" tf:"auto_connect,omitempty"`

	// (Number) Turn on the captive portal after the specified amount of time.
	// Turn on the captive portal after the specified amount of time.
	CaptivePortal *float64 `json:"captivePortal,omitempty" tf:"captive_portal,omitempty"`

	// (Boolean) If the dns_server field of a fallback domain is not present, the client will fall back to a best guess of the default/system DNS resolvers unless this policy option is set to true.
	// If the `dns_server` field of a fallback domain is not present, the client will fall back to a best guess of the default/system DNS resolvers unless this policy option is set to `true`.
	DisableAutoFallback *bool `json:"disableAutoFallback,omitempty" tf:"disable_auto_fallback,omitempty"`

	// (Attributes List) (see below for nested schema)
	Exclude []TrustDeviceDefaultProfileExcludeInitParameters `json:"exclude,omitempty" tf:"exclude,omitempty"`

	// (Boolean) Whether to add Microsoft IPs to Split Tunnel exclusions.
	// Whether to add Microsoft IPs to Split Tunnel exclusions.
	ExcludeOfficeIps *bool `json:"excludeOfficeIps,omitempty" tf:"exclude_office_ips,omitempty"`

	// (Attributes List) (see below for nested schema)
	FallbackDomains []TrustDeviceDefaultProfileFallbackDomainsInitParameters `json:"fallbackDomains,omitempty" tf:"fallback_domains,omitempty"`

	// (Attributes List) (see below for nested schema)
	Include []TrustDeviceDefaultProfileIncludeInitParameters `json:"include,omitempty" tf:"include,omitempty"`

	// (Attributes) (see below for nested schema)
	ServiceModeV2 *TrustDeviceDefaultProfileServiceModeV2InitParameters `json:"serviceModeV2,omitempty" tf:"service_mode_v2,omitempty"`

	// (String) The URL to launch when the Send Feedback button is clicked.
	// The URL to launch when the Send Feedback button is clicked.
	SupportURL *string `json:"supportUrl,omitempty" tf:"support_url,omitempty"`

	// (Boolean) Whether to allow the user to turn off the WARP switch and disconnect the client.
	// Whether to allow the user to turn off the WARP switch and disconnect the client.
	SwitchLocked *bool `json:"switchLocked,omitempty" tf:"switch_locked,omitempty"`

	// (String) Determines which tunnel protocol to use.
	// Determines which tunnel protocol to use.
	TunnelProtocol *string `json:"tunnelProtocol,omitempty" tf:"tunnel_protocol,omitempty"`
}

type TrustDeviceDefaultProfileObservation struct {

	// (String)
	AccountID *string `json:"accountId,omitempty" tf:"account_id,omitempty"`

	// (Boolean) Whether to allow the user to switch WARP between modes.
	// Whether to allow the user to switch WARP between modes.
	AllowModeSwitch *bool `json:"allowModeSwitch,omitempty" tf:"allow_mode_switch,omitempty"`

	// (Boolean) Whether to receive update notifications when a new version of the client is available.
	// Whether to receive update notifications when a new version of the client is available.
	AllowUpdates *bool `json:"allowUpdates,omitempty" tf:"allow_updates,omitempty"`

	// (Boolean) Whether to allow devices to leave the organization.
	// Whether to allow devices to leave the organization.
	AllowedToLeave *bool `json:"allowedToLeave,omitempty" tf:"allowed_to_leave,omitempty"`

	// (Number) The amount of time in seconds to reconnect after having been disabled.
	// The amount of time in seconds to reconnect after having been disabled.
	AutoConnect *float64 `json:"autoConnect,omitempty" tf:"auto_connect,omitempty"`

	// (Number) Turn on the captive portal after the specified amount of time.
	// Turn on the captive portal after the specified amount of time.
	CaptivePortal *float64 `json:"captivePortal,omitempty" tf:"captive_portal,omitempty"`

	// (Boolean) Whether the policy will be applied to matching devices.
	// Whether the policy will be applied to matching devices.
	Default *bool `json:"default,omitempty" tf:"default,omitempty"`

	// (Boolean) If the dns_server field of a fallback domain is not present, the client will fall back to a best guess of the default/system DNS resolvers unless this policy option is set to true.
	// If the `dns_server` field of a fallback domain is not present, the client will fall back to a best guess of the default/system DNS resolvers unless this policy option is set to `true`.
	DisableAutoFallback *bool `json:"disableAutoFallback,omitempty" tf:"disable_auto_fallback,omitempty"`

	// (Boolean) Whether the policy will be applied to matching devices.
	// Whether the policy will be applied to matching devices.
	Enabled *bool `json:"enabled,omitempty" tf:"enabled,omitempty"`

	// (Attributes List) (see below for nested schema)
	Exclude []TrustDeviceDefaultProfileExcludeObservation `json:"exclude,omitempty" tf:"exclude,omitempty"`

	// (Boolean) Whether to add Microsoft IPs to Split Tunnel exclusions.
	// Whether to add Microsoft IPs to Split Tunnel exclusions.
	ExcludeOfficeIps *bool `json:"excludeOfficeIps,omitempty" tf:"exclude_office_ips,omitempty"`

	// (Attributes List) (see below for nested schema)
	FallbackDomains []TrustDeviceDefaultProfileFallbackDomainsObservation `json:"fallbackDomains,omitempty" tf:"fallback_domains,omitempty"`

	// (String)
	GatewayUniqueID *string `json:"gatewayUniqueId,omitempty" tf:"gateway_unique_id,omitempty"`

	// (String) The ID of this resource.
	ID *string `json:"id,omitempty" tf:"id,omitempty"`

	// (Attributes List) (see below for nested schema)
	Include []TrustDeviceDefaultProfileIncludeObservation `json:"include,omitempty" tf:"include,omitempty"`

	// (Attributes) (see below for nested schema)
	ServiceModeV2 *TrustDeviceDefaultProfileServiceModeV2Observation `json:"serviceModeV2,omitempty" tf:"service_mode_v2,omitempty"`

	// (String) The URL to launch when the Send Feedback button is clicked.
	// The URL to launch when the Send Feedback button is clicked.
	SupportURL *string `json:"supportUrl,omitempty" tf:"support_url,omitempty"`

	// (Boolean) Whether to allow the user to turn off the WARP switch and disconnect the client.
	// Whether to allow the user to turn off the WARP switch and disconnect the client.
	SwitchLocked *bool `json:"switchLocked,omitempty" tf:"switch_locked,omitempty"`

	// (String) Determines which tunnel protocol to use.
	// Determines which tunnel protocol to use.
	TunnelProtocol *string `json:"tunnelProtocol,omitempty" tf:"tunnel_protocol,omitempty"`
}

type TrustDeviceDefaultProfileParameters struct {

	// (String)
	// +kubebuilder:validation:Optional
	AccountID *string `json:"accountId,omitempty" tf:"account_id,omitempty"`

	// (Boolean) Whether to allow the user to switch WARP between modes.
	// Whether to allow the user to switch WARP between modes.
	// +kubebuilder:validation:Optional
	AllowModeSwitch *bool `json:"allowModeSwitch,omitempty" tf:"allow_mode_switch,omitempty"`

	// (Boolean) Whether to receive update notifications when a new version of the client is available.
	// Whether to receive update notifications when a new version of the client is available.
	// +kubebuilder:validation:Optional
	AllowUpdates *bool `json:"allowUpdates,omitempty" tf:"allow_updates,omitempty"`

	// (Boolean) Whether to allow devices to leave the organization.
	// Whether to allow devices to leave the organization.
	// +kubebuilder:validation:Optional
	AllowedToLeave *bool `json:"allowedToLeave,omitempty" tf:"allowed_to_leave,omitempty"`

	// (Number) The amount of time in seconds to reconnect after having been disabled.
	// The amount of time in seconds to reconnect after having been disabled.
	// +kubebuilder:validation:Optional
	AutoConnect *float64 `json:"autoConnect,omitempty" tf:"auto_connect,omitempty"`

	// (Number) Turn on the captive portal after the specified amount of time.
	// Turn on the captive portal after the specified amount of time.
	// +kubebuilder:validation:Optional
	CaptivePortal *float64 `json:"captivePortal,omitempty" tf:"captive_portal,omitempty"`

	// (Boolean) If the dns_server field of a fallback domain is not present, the client will fall back to a best guess of the default/system DNS resolvers unless this policy option is set to true.
	// If the `dns_server` field of a fallback domain is not present, the client will fall back to a best guess of the default/system DNS resolvers unless this policy option is set to `true`.
	// +kubebuilder:validation:Optional
	DisableAutoFallback *bool `json:"disableAutoFallback,omitempty" tf:"disable_auto_fallback,omitempty"`

	// (Attributes List) (see below for nested schema)
	// +kubebuilder:validation:Optional
	Exclude []TrustDeviceDefaultProfileExcludeParameters `json:"exclude,omitempty" tf:"exclude,omitempty"`

	// (Boolean) Whether to add Microsoft IPs to Split Tunnel exclusions.
	// Whether to add Microsoft IPs to Split Tunnel exclusions.
	// +kubebuilder:validation:Optional
	ExcludeOfficeIps *bool `json:"excludeOfficeIps,omitempty" tf:"exclude_office_ips,omitempty"`

	// (Attributes List) (see below for nested schema)
	// +kubebuilder:validation:Optional
	FallbackDomains []TrustDeviceDefaultProfileFallbackDomainsParameters `json:"fallbackDomains,omitempty" tf:"fallback_domains,omitempty"`

	// (Attributes List) (see below for nested schema)
	// +kubebuilder:validation:Optional
	Include []TrustDeviceDefaultProfileIncludeParameters `json:"include,omitempty" tf:"include,omitempty"`

	// (Attributes) (see below for nested schema)
	// +kubebuilder:validation:Optional
	ServiceModeV2 *TrustDeviceDefaultProfileServiceModeV2Parameters `json:"serviceModeV2,omitempty" tf:"service_mode_v2,omitempty"`

	// (String) The URL to launch when the Send Feedback button is clicked.
	// The URL to launch when the Send Feedback button is clicked.
	// +kubebuilder:validation:Optional
	SupportURL *string `json:"supportUrl,omitempty" tf:"support_url,omitempty"`

	// (Boolean) Whether to allow the user to turn off the WARP switch and disconnect the client.
	// Whether to allow the user to turn off the WARP switch and disconnect the client.
	// +kubebuilder:validation:Optional
	SwitchLocked *bool `json:"switchLocked,omitempty" tf:"switch_locked,omitempty"`

	// (String) Determines which tunnel protocol to use.
	// Determines which tunnel protocol to use.
	// +kubebuilder:validation:Optional
	TunnelProtocol *string `json:"tunnelProtocol,omitempty" tf:"tunnel_protocol,omitempty"`
}

type TrustDeviceDefaultProfileServiceModeV2InitParameters struct {

	// (String) The mode to run the WARP client under.
	// The mode to run the WARP client under.
	Mode *string `json:"mode,omitempty" tf:"mode,omitempty"`

	// (Number) The port number when used with proxy mode.
	// The port number when used with proxy mode.
	Port *float64 `json:"port,omitempty" tf:"port,omitempty"`
}

type TrustDeviceDefaultProfileServiceModeV2Observation struct {

	// (String) The mode to run the WARP client under.
	// The mode to run the WARP client under.
	Mode *string `json:"mode,omitempty" tf:"mode,omitempty"`

	// (Number) The port number when used with proxy mode.
	// The port number when used with proxy mode.
	Port *float64 `json:"port,omitempty" tf:"port,omitempty"`
}

type TrustDeviceDefaultProfileServiceModeV2Parameters struct {

	// (String) The mode to run the WARP client under.
	// The mode to run the WARP client under.
	// +kubebuilder:validation:Optional
	Mode *string `json:"mode,omitempty" tf:"mode,omitempty"`

	// (Number) The port number when used with proxy mode.
	// The port number when used with proxy mode.
	// +kubebuilder:validation:Optional
	Port *float64 `json:"port,omitempty" tf:"port,omitempty"`
}

// TrustDeviceDefaultProfileSpec defines the desired state of TrustDeviceDefaultProfile
type TrustDeviceDefaultProfileSpec struct {
	v1.ResourceSpec `json:",inline"`
	ForProvider     TrustDeviceDefaultProfileParameters `json:"forProvider"`
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
	InitProvider TrustDeviceDefaultProfileInitParameters `json:"initProvider,omitempty"`
}

// TrustDeviceDefaultProfileStatus defines the observed state of TrustDeviceDefaultProfile.
type TrustDeviceDefaultProfileStatus struct {
	v1.ResourceStatus `json:",inline"`
	AtProvider        TrustDeviceDefaultProfileObservation `json:"atProvider,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:storageversion

// TrustDeviceDefaultProfile is the Schema for the TrustDeviceDefaultProfiles API.
// +kubebuilder:printcolumn:name="SYNCED",type="string",JSONPath=".status.conditions[?(@.type=='Synced')].status"
// +kubebuilder:printcolumn:name="READY",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="EXTERNAL-NAME",type="string",JSONPath=".metadata.annotations.crossplane\\.io/external-name"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:resource:scope=Cluster,categories={crossplane,managed,cloudflare}
type TrustDeviceDefaultProfile struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.accountId) || (has(self.initProvider) && has(self.initProvider.accountId))",message="spec.forProvider.accountId is a required parameter"
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.exclude) || (has(self.initProvider) && has(self.initProvider.exclude))",message="spec.forProvider.exclude is a required parameter"
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.fallbackDomains) || (has(self.initProvider) && has(self.initProvider.fallbackDomains))",message="spec.forProvider.fallbackDomains is a required parameter"
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.include) || (has(self.initProvider) && has(self.initProvider.include))",message="spec.forProvider.include is a required parameter"
	Spec   TrustDeviceDefaultProfileSpec   `json:"spec"`
	Status TrustDeviceDefaultProfileStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// TrustDeviceDefaultProfileList contains a list of TrustDeviceDefaultProfiles
type TrustDeviceDefaultProfileList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []TrustDeviceDefaultProfile `json:"items"`
}

// Repository type metadata.
var (
	TrustDeviceDefaultProfile_Kind             = "TrustDeviceDefaultProfile"
	TrustDeviceDefaultProfile_GroupKind        = schema.GroupKind{Group: CRDGroup, Kind: TrustDeviceDefaultProfile_Kind}.String()
	TrustDeviceDefaultProfile_KindAPIVersion   = TrustDeviceDefaultProfile_Kind + "." + CRDGroupVersion.String()
	TrustDeviceDefaultProfile_GroupVersionKind = CRDGroupVersion.WithKind(TrustDeviceDefaultProfile_Kind)
)

func init() {
	SchemeBuilder.Register(&TrustDeviceDefaultProfile{}, &TrustDeviceDefaultProfileList{})
}
