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

type CustomCertBundleInitParameters struct {

	// (String) If a custom uploaded certificate is used.
	// If a custom uploaded certificate is used.
	CustomCertificate *string `json:"customCertificate,omitempty" tf:"custom_certificate,omitempty"`

	// (String) The key for a custom uploaded certificate.
	// The key for a custom uploaded certificate.
	CustomKey *string `json:"customKey,omitempty" tf:"custom_key,omitempty"`
}

type CustomCertBundleObservation struct {

	// (String) If a custom uploaded certificate is used.
	// If a custom uploaded certificate is used.
	CustomCertificate *string `json:"customCertificate,omitempty" tf:"custom_certificate,omitempty"`

	// (String) The key for a custom uploaded certificate.
	// The key for a custom uploaded certificate.
	CustomKey *string `json:"customKey,omitempty" tf:"custom_key,omitempty"`
}

type CustomCertBundleParameters struct {

	// (String) If a custom uploaded certificate is used.
	// If a custom uploaded certificate is used.
	// +kubebuilder:validation:Optional
	CustomCertificate *string `json:"customCertificate" tf:"custom_certificate,omitempty"`

	// (String) The key for a custom uploaded certificate.
	// The key for a custom uploaded certificate.
	// +kubebuilder:validation:Optional
	CustomKey *string `json:"customKey" tf:"custom_key,omitempty"`
}

type HostnameInitParameters struct {

	// hostname (customer) settings.
	// Unique key/value metadata for this hostname. These are per-hostname (customer) settings.
	// +mapType=granular
	CustomMetadata map[string]*string `json:"customMetadata,omitempty" tf:"custom_metadata,omitempty"`

	// (String) a valid hostname that’s been added to your DNS zone as an A, AAAA, or CNAME record.
	// a valid hostname that’s been added to your DNS zone as an A, AAAA, or CNAME record.
	CustomOriginServer *string `json:"customOriginServer,omitempty" tf:"custom_origin_server,omitempty"`

	// (String) A hostname that will be sent to your custom origin server as SNI for TLS handshake. This can be a valid subdomain of the zone or custom origin server name or the string ':request_host_header:' which will cause the host header in the request to be used as SNI. Not configurable with default/fallback origin server.
	// A hostname that will be sent to your custom origin server as SNI for TLS handshake. This can be a valid subdomain of the zone or custom origin server name or the string ':request_host_header:' which will cause the host header in the request to be used as SNI. Not configurable with default/fallback origin server.
	CustomOriginSni *string `json:"customOriginSni,omitempty" tf:"custom_origin_sni,omitempty"`

	// (String) The custom hostname that will point to your hostname via CNAME.
	// The custom hostname that will point to your hostname via CNAME.
	Hostname *string `json:"hostname,omitempty" tf:"hostname,omitempty"`

	// (Attributes) This is a record which can be placed to activate a hostname. (see below for nested schema)
	OwnershipVerification *OwnershipVerificationInitParameters `json:"ownershipVerification,omitempty" tf:"ownership_verification,omitempty"`

	// (Attributes) This presents the token to be served by the given http url to activate a hostname. (see below for nested schema)
	OwnershipVerificationHTTP *OwnershipVerificationHTTPInitParameters `json:"ownershipVerificationHttp,omitempty" tf:"ownership_verification_http,omitempty"`

	// (Attributes) SSL properties used when creating the custom hostname. (see below for nested schema)
	SSL *SSLInitParameters `json:"ssl,omitempty" tf:"ssl,omitempty"`

	// (String) Identifier
	// Identifier
	ZoneID *string `json:"zoneId,omitempty" tf:"zone_id,omitempty"`
}

type HostnameObservation struct {

	// (String) This is the time the hostname was created.
	// This is the time the hostname was created.
	CreatedAt *string `json:"createdAt,omitempty" tf:"created_at,omitempty"`

	// hostname (customer) settings.
	// Unique key/value metadata for this hostname. These are per-hostname (customer) settings.
	// +mapType=granular
	CustomMetadata map[string]*string `json:"customMetadata,omitempty" tf:"custom_metadata,omitempty"`

	// (String) a valid hostname that’s been added to your DNS zone as an A, AAAA, or CNAME record.
	// a valid hostname that’s been added to your DNS zone as an A, AAAA, or CNAME record.
	CustomOriginServer *string `json:"customOriginServer,omitempty" tf:"custom_origin_server,omitempty"`

	// (String) A hostname that will be sent to your custom origin server as SNI for TLS handshake. This can be a valid subdomain of the zone or custom origin server name or the string ':request_host_header:' which will cause the host header in the request to be used as SNI. Not configurable with default/fallback origin server.
	// A hostname that will be sent to your custom origin server as SNI for TLS handshake. This can be a valid subdomain of the zone or custom origin server name or the string ':request_host_header:' which will cause the host header in the request to be used as SNI. Not configurable with default/fallback origin server.
	CustomOriginSni *string `json:"customOriginSni,omitempty" tf:"custom_origin_sni,omitempty"`

	// (String) The custom hostname that will point to your hostname via CNAME.
	// The custom hostname that will point to your hostname via CNAME.
	Hostname *string `json:"hostname,omitempty" tf:"hostname,omitempty"`

	// (String) Identifier
	ID *string `json:"id,omitempty" tf:"id,omitempty"`

	// (Attributes) This is a record which can be placed to activate a hostname. (see below for nested schema)
	OwnershipVerification *OwnershipVerificationObservation `json:"ownershipVerification,omitempty" tf:"ownership_verification,omitempty"`

	// (Attributes) This presents the token to be served by the given http url to activate a hostname. (see below for nested schema)
	OwnershipVerificationHTTP *OwnershipVerificationHTTPObservation `json:"ownershipVerificationHttp,omitempty" tf:"ownership_verification_http,omitempty"`

	// (Attributes) SSL properties used when creating the custom hostname. (see below for nested schema)
	SSL *SSLObservation `json:"ssl,omitempty" tf:"ssl,omitempty"`

	// (String) Status of the hostname's activation.
	// Status of the hostname's activation.
	Status *string `json:"status,omitempty" tf:"status,omitempty"`

	// (List of String) These are errors that were encountered while trying to activate a hostname.
	// These are errors that were encountered while trying to activate a hostname.
	VerificationErrors []*string `json:"verificationErrors,omitempty" tf:"verification_errors,omitempty"`

	// (String) Identifier
	// Identifier
	ZoneID *string `json:"zoneId,omitempty" tf:"zone_id,omitempty"`
}

type HostnameParameters struct {

	// hostname (customer) settings.
	// Unique key/value metadata for this hostname. These are per-hostname (customer) settings.
	// +kubebuilder:validation:Optional
	// +mapType=granular
	CustomMetadata map[string]*string `json:"customMetadata,omitempty" tf:"custom_metadata,omitempty"`

	// (String) a valid hostname that’s been added to your DNS zone as an A, AAAA, or CNAME record.
	// a valid hostname that’s been added to your DNS zone as an A, AAAA, or CNAME record.
	// +kubebuilder:validation:Optional
	CustomOriginServer *string `json:"customOriginServer,omitempty" tf:"custom_origin_server,omitempty"`

	// (String) A hostname that will be sent to your custom origin server as SNI for TLS handshake. This can be a valid subdomain of the zone or custom origin server name or the string ':request_host_header:' which will cause the host header in the request to be used as SNI. Not configurable with default/fallback origin server.
	// A hostname that will be sent to your custom origin server as SNI for TLS handshake. This can be a valid subdomain of the zone or custom origin server name or the string ':request_host_header:' which will cause the host header in the request to be used as SNI. Not configurable with default/fallback origin server.
	// +kubebuilder:validation:Optional
	CustomOriginSni *string `json:"customOriginSni,omitempty" tf:"custom_origin_sni,omitempty"`

	// (String) The custom hostname that will point to your hostname via CNAME.
	// The custom hostname that will point to your hostname via CNAME.
	// +kubebuilder:validation:Optional
	Hostname *string `json:"hostname,omitempty" tf:"hostname,omitempty"`

	// (Attributes) This is a record which can be placed to activate a hostname. (see below for nested schema)
	// +kubebuilder:validation:Optional
	OwnershipVerification *OwnershipVerificationParameters `json:"ownershipVerification,omitempty" tf:"ownership_verification,omitempty"`

	// (Attributes) This presents the token to be served by the given http url to activate a hostname. (see below for nested schema)
	// +kubebuilder:validation:Optional
	OwnershipVerificationHTTP *OwnershipVerificationHTTPParameters `json:"ownershipVerificationHttp,omitempty" tf:"ownership_verification_http,omitempty"`

	// (Attributes) SSL properties used when creating the custom hostname. (see below for nested schema)
	// +kubebuilder:validation:Optional
	SSL *SSLParameters `json:"ssl,omitempty" tf:"ssl,omitempty"`

	// (String) Identifier
	// Identifier
	// +kubebuilder:validation:Optional
	ZoneID *string `json:"zoneId,omitempty" tf:"zone_id,omitempty"`
}

type OwnershipVerificationHTTPInitParameters struct {
}

type OwnershipVerificationHTTPObservation struct {

	// (String) Token to be served.
	// Token to be served.
	HTTPBody *string `json:"httpBody,omitempty" tf:"http_body,omitempty"`

	// (String) The HTTP URL that will be checked during custom hostname verification and where the customer should host the token.
	// The HTTP URL that will be checked during custom hostname verification and where the customer should host the token.
	HTTPURL *string `json:"httpUrl,omitempty" tf:"http_url,omitempty"`
}

type OwnershipVerificationHTTPParameters struct {
}

type OwnershipVerificationInitParameters struct {
}

type OwnershipVerificationObservation struct {

	// (String) DNS Name for record.
	// DNS Name for record.
	Name *string `json:"name,omitempty" tf:"name,omitempty"`

	// (String) Level of validation to be used for this hostname. Domain validation (dv) must be used.
	// DNS Record type.
	Type *string `json:"type,omitempty" tf:"type,omitempty"`

	// (String) Content for the record.
	// Content for the record.
	Value *string `json:"value,omitempty" tf:"value,omitempty"`
}

type OwnershipVerificationParameters struct {
}

type SSLInitParameters struct {

	// (String) A ubiquitous bundle has the highest probability of being verified everywhere, even by clients using outdated or unusual trust stores. An optimal bundle uses the shortest chain and newest intermediates. And the force bundle verifies the chain, but does not otherwise modify it.
	// A ubiquitous bundle has the highest probability of being verified everywhere, even by clients using outdated or unusual trust stores. An optimal bundle uses the shortest chain and newest intermediates. And the force bundle verifies the chain, but does not otherwise modify it.
	BundleMethod *string `json:"bundleMethod,omitempty" tf:"bundle_method,omitempty"`

	// (String) The Certificate Authority that will issue the certificate
	// The Certificate Authority that will issue the certificate
	CertificateAuthority *string `json:"certificateAuthority,omitempty" tf:"certificate_authority,omitempty"`

	// (Boolean) Whether or not to add Cloudflare Branding for the order.  This will add a subdomain of sni.cloudflaressl.com as the Common Name if set to true
	// Whether or not to add Cloudflare Branding for the order.  This will add a subdomain of sni.cloudflaressl.com as the Common Name if set to true
	CloudflareBranding *bool `json:"cloudflareBranding,omitempty" tf:"cloudflare_branding,omitempty"`

	// (Attributes List) Array of custom certificate and key pairs (1 or 2 pairs allowed) (see below for nested schema)
	CustomCertBundle []CustomCertBundleInitParameters `json:"customCertBundle,omitempty" tf:"custom_cert_bundle,omitempty"`

	// (String) If a custom uploaded certificate is used.
	// If a custom uploaded certificate is used.
	CustomCertificate *string `json:"customCertificate,omitempty" tf:"custom_certificate,omitempty"`

	// (String) The key for a custom uploaded certificate.
	// The key for a custom uploaded certificate.
	CustomKey *string `json:"customKey,omitempty" tf:"custom_key,omitempty"`

	// (String) Domain control validation (DCV) method used for this hostname.
	// Domain control validation (DCV) method used for this hostname.
	Method *string `json:"method,omitempty" tf:"method,omitempty"`

	// (Attributes) SSL specific settings. (see below for nested schema)
	Settings *SettingsInitParameters `json:"settings,omitempty" tf:"settings,omitempty"`

	// (String) Level of validation to be used for this hostname. Domain validation (dv) must be used.
	// Level of validation to be used for this hostname. Domain validation (dv) must be used.
	Type *string `json:"type,omitempty" tf:"type,omitempty"`

	// (Boolean) Indicates whether the certificate covers a wildcard.
	// Indicates whether the certificate covers a wildcard.
	Wildcard *bool `json:"wildcard,omitempty" tf:"wildcard,omitempty"`
}

type SSLObservation struct {

	// (String) A ubiquitous bundle has the highest probability of being verified everywhere, even by clients using outdated or unusual trust stores. An optimal bundle uses the shortest chain and newest intermediates. And the force bundle verifies the chain, but does not otherwise modify it.
	// A ubiquitous bundle has the highest probability of being verified everywhere, even by clients using outdated or unusual trust stores. An optimal bundle uses the shortest chain and newest intermediates. And the force bundle verifies the chain, but does not otherwise modify it.
	BundleMethod *string `json:"bundleMethod,omitempty" tf:"bundle_method,omitempty"`

	// (String) The Certificate Authority that will issue the certificate
	// The Certificate Authority that will issue the certificate
	CertificateAuthority *string `json:"certificateAuthority,omitempty" tf:"certificate_authority,omitempty"`

	// (Boolean) Whether or not to add Cloudflare Branding for the order.  This will add a subdomain of sni.cloudflaressl.com as the Common Name if set to true
	// Whether or not to add Cloudflare Branding for the order.  This will add a subdomain of sni.cloudflaressl.com as the Common Name if set to true
	CloudflareBranding *bool `json:"cloudflareBranding,omitempty" tf:"cloudflare_branding,omitempty"`

	// (Attributes List) Array of custom certificate and key pairs (1 or 2 pairs allowed) (see below for nested schema)
	CustomCertBundle []CustomCertBundleObservation `json:"customCertBundle,omitempty" tf:"custom_cert_bundle,omitempty"`

	// (String) If a custom uploaded certificate is used.
	// If a custom uploaded certificate is used.
	CustomCertificate *string `json:"customCertificate,omitempty" tf:"custom_certificate,omitempty"`

	// (String) The key for a custom uploaded certificate.
	// The key for a custom uploaded certificate.
	CustomKey *string `json:"customKey,omitempty" tf:"custom_key,omitempty"`

	// (String) Domain control validation (DCV) method used for this hostname.
	// Domain control validation (DCV) method used for this hostname.
	Method *string `json:"method,omitempty" tf:"method,omitempty"`

	// (Attributes) SSL specific settings. (see below for nested schema)
	Settings *SettingsObservation `json:"settings,omitempty" tf:"settings,omitempty"`

	// (String) Level of validation to be used for this hostname. Domain validation (dv) must be used.
	// Level of validation to be used for this hostname. Domain validation (dv) must be used.
	Type *string `json:"type,omitempty" tf:"type,omitempty"`

	// (Boolean) Indicates whether the certificate covers a wildcard.
	// Indicates whether the certificate covers a wildcard.
	Wildcard *bool `json:"wildcard,omitempty" tf:"wildcard,omitempty"`
}

type SSLParameters struct {

	// (String) A ubiquitous bundle has the highest probability of being verified everywhere, even by clients using outdated or unusual trust stores. An optimal bundle uses the shortest chain and newest intermediates. And the force bundle verifies the chain, but does not otherwise modify it.
	// A ubiquitous bundle has the highest probability of being verified everywhere, even by clients using outdated or unusual trust stores. An optimal bundle uses the shortest chain and newest intermediates. And the force bundle verifies the chain, but does not otherwise modify it.
	// +kubebuilder:validation:Optional
	BundleMethod *string `json:"bundleMethod,omitempty" tf:"bundle_method,omitempty"`

	// (String) The Certificate Authority that will issue the certificate
	// The Certificate Authority that will issue the certificate
	// +kubebuilder:validation:Optional
	CertificateAuthority *string `json:"certificateAuthority,omitempty" tf:"certificate_authority,omitempty"`

	// (Boolean) Whether or not to add Cloudflare Branding for the order.  This will add a subdomain of sni.cloudflaressl.com as the Common Name if set to true
	// Whether or not to add Cloudflare Branding for the order.  This will add a subdomain of sni.cloudflaressl.com as the Common Name if set to true
	// +kubebuilder:validation:Optional
	CloudflareBranding *bool `json:"cloudflareBranding,omitempty" tf:"cloudflare_branding,omitempty"`

	// (Attributes List) Array of custom certificate and key pairs (1 or 2 pairs allowed) (see below for nested schema)
	// +kubebuilder:validation:Optional
	CustomCertBundle []CustomCertBundleParameters `json:"customCertBundle" tf:"custom_cert_bundle,omitempty"`

	// (String) If a custom uploaded certificate is used.
	// If a custom uploaded certificate is used.
	// +kubebuilder:validation:Optional
	CustomCertificate *string `json:"customCertificate,omitempty" tf:"custom_certificate,omitempty"`

	// (String) The key for a custom uploaded certificate.
	// The key for a custom uploaded certificate.
	// +kubebuilder:validation:Optional
	CustomKey *string `json:"customKey,omitempty" tf:"custom_key,omitempty"`

	// (String) Domain control validation (DCV) method used for this hostname.
	// Domain control validation (DCV) method used for this hostname.
	// +kubebuilder:validation:Optional
	Method *string `json:"method,omitempty" tf:"method,omitempty"`

	// (Attributes) SSL specific settings. (see below for nested schema)
	// +kubebuilder:validation:Optional
	Settings *SettingsParameters `json:"settings,omitempty" tf:"settings,omitempty"`

	// (String) Level of validation to be used for this hostname. Domain validation (dv) must be used.
	// Level of validation to be used for this hostname. Domain validation (dv) must be used.
	// +kubebuilder:validation:Optional
	Type *string `json:"type,omitempty" tf:"type,omitempty"`

	// (Boolean) Indicates whether the certificate covers a wildcard.
	// Indicates whether the certificate covers a wildcard.
	// +kubebuilder:validation:Optional
	Wildcard *bool `json:"wildcard,omitempty" tf:"wildcard,omitempty"`
}

type SettingsInitParameters struct {

	// (List of String) An allowlist of ciphers for TLS termination. These ciphers must be in the BoringSSL format.
	// An allowlist of ciphers for TLS termination. These ciphers must be in the BoringSSL format.
	Ciphers []*string `json:"ciphers,omitempty" tf:"ciphers,omitempty"`

	// (String) Whether or not Early Hints is enabled.
	// Whether or not Early Hints is enabled.
	EarlyHints *string `json:"earlyHints,omitempty" tf:"early_hints,omitempty"`

	// (String) Whether or not HTTP2 is enabled.
	// Whether or not HTTP2 is enabled.
	Http2 *string `json:"http2,omitempty" tf:"http2,omitempty"`

	// (String) The minimum TLS version supported.
	// The minimum TLS version supported.
	MinTLSVersion *string `json:"minTlsVersion,omitempty" tf:"min_tls_version,omitempty"`

	// (String) Whether or not TLS 1.3 is enabled.
	// Whether or not TLS 1.3 is enabled.
	TLS13 *string `json:"tls13,omitempty" tf:"tls_1_3,omitempty"`
}

type SettingsObservation struct {

	// (List of String) An allowlist of ciphers for TLS termination. These ciphers must be in the BoringSSL format.
	// An allowlist of ciphers for TLS termination. These ciphers must be in the BoringSSL format.
	Ciphers []*string `json:"ciphers,omitempty" tf:"ciphers,omitempty"`

	// (String) Whether or not Early Hints is enabled.
	// Whether or not Early Hints is enabled.
	EarlyHints *string `json:"earlyHints,omitempty" tf:"early_hints,omitempty"`

	// (String) Whether or not HTTP2 is enabled.
	// Whether or not HTTP2 is enabled.
	Http2 *string `json:"http2,omitempty" tf:"http2,omitempty"`

	// (String) The minimum TLS version supported.
	// The minimum TLS version supported.
	MinTLSVersion *string `json:"minTlsVersion,omitempty" tf:"min_tls_version,omitempty"`

	// (String) Whether or not TLS 1.3 is enabled.
	// Whether or not TLS 1.3 is enabled.
	TLS13 *string `json:"tls13,omitempty" tf:"tls_1_3,omitempty"`
}

type SettingsParameters struct {

	// (List of String) An allowlist of ciphers for TLS termination. These ciphers must be in the BoringSSL format.
	// An allowlist of ciphers for TLS termination. These ciphers must be in the BoringSSL format.
	// +kubebuilder:validation:Optional
	Ciphers []*string `json:"ciphers,omitempty" tf:"ciphers,omitempty"`

	// (String) Whether or not Early Hints is enabled.
	// Whether or not Early Hints is enabled.
	// +kubebuilder:validation:Optional
	EarlyHints *string `json:"earlyHints,omitempty" tf:"early_hints,omitempty"`

	// (String) Whether or not HTTP2 is enabled.
	// Whether or not HTTP2 is enabled.
	// +kubebuilder:validation:Optional
	Http2 *string `json:"http2,omitempty" tf:"http2,omitempty"`

	// (String) The minimum TLS version supported.
	// The minimum TLS version supported.
	// +kubebuilder:validation:Optional
	MinTLSVersion *string `json:"minTlsVersion,omitempty" tf:"min_tls_version,omitempty"`

	// (String) Whether or not TLS 1.3 is enabled.
	// Whether or not TLS 1.3 is enabled.
	// +kubebuilder:validation:Optional
	TLS13 *string `json:"tls13,omitempty" tf:"tls_1_3,omitempty"`
}

// HostnameSpec defines the desired state of Hostname
type HostnameSpec struct {
	v1.ResourceSpec `json:",inline"`
	ForProvider     HostnameParameters `json:"forProvider"`
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
	InitProvider HostnameInitParameters `json:"initProvider,omitempty"`
}

// HostnameStatus defines the observed state of Hostname.
type HostnameStatus struct {
	v1.ResourceStatus `json:",inline"`
	AtProvider        HostnameObservation `json:"atProvider,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:storageversion

// Hostname is the Schema for the Hostnames API.
// +kubebuilder:printcolumn:name="SYNCED",type="string",JSONPath=".status.conditions[?(@.type=='Synced')].status"
// +kubebuilder:printcolumn:name="READY",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="EXTERNAL-NAME",type="string",JSONPath=".metadata.annotations.crossplane\\.io/external-name"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:resource:scope=Cluster,categories={crossplane,managed,cloudflare-upjet}
type Hostname struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.hostname) || (has(self.initProvider) && has(self.initProvider.hostname))",message="spec.forProvider.hostname is a required parameter"
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.zoneId) || (has(self.initProvider) && has(self.initProvider.zoneId))",message="spec.forProvider.zoneId is a required parameter"
	Spec   HostnameSpec   `json:"spec"`
	Status HostnameStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// HostnameList contains a list of Hostnames
type HostnameList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Hostname `json:"items"`
}

// Repository type metadata.
var (
	Hostname_Kind             = "Hostname"
	Hostname_GroupKind        = schema.GroupKind{Group: CRDGroup, Kind: Hostname_Kind}.String()
	Hostname_KindAPIVersion   = Hostname_Kind + "." + CRDGroupVersion.String()
	Hostname_GroupVersionKind = CRDGroupVersion.WithKind(Hostname_Kind)
)

func init() {
	SchemeBuilder.Register(&Hostname{}, &HostnameList{})
}
