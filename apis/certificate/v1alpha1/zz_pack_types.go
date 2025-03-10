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

type PackInitParameters struct {

	// (String) Certificate Authority selected for the order.  For information on any certificate authority specific details or restrictions see this page for more details.
	// Certificate Authority selected for the order.  For information on any certificate authority specific details or restrictions [see this page for more details.](https://developers.cloudflare.com/ssl/reference/certificate-authorities)
	CertificateAuthority *string `json:"certificateAuthority,omitempty" tf:"certificate_authority,omitempty"`

	// (Boolean) Whether or not to add Cloudflare Branding for the order.  This will add a subdomain of sni.cloudflaressl.com as the Common Name if set to true.
	// Whether or not to add Cloudflare Branding for the order.  This will add a subdomain of sni.cloudflaressl.com as the Common Name if set to true.
	CloudflareBranding *bool `json:"cloudflareBranding,omitempty" tf:"cloudflare_branding,omitempty"`

	// (List of String) Comma separated list of valid host names for the certificate packs. Must contain the zone apex, may not contain more than 50 hosts, and may not be empty.
	// Comma separated list of valid host names for the certificate packs. Must contain the zone apex, may not contain more than 50 hosts, and may not be empty.
	Hosts []*string `json:"hosts,omitempty" tf:"hosts,omitempty"`

	// (String) Type of certificate pack.
	// Type of certificate pack.
	Type *string `json:"type,omitempty" tf:"type,omitempty"`

	// (String) Validation Method selected for the order.
	// Validation Method selected for the order.
	ValidationMethod *string `json:"validationMethod,omitempty" tf:"validation_method,omitempty"`

	// (Number) Validity Days selected for the order.
	// Validity Days selected for the order.
	ValidityDays *float64 `json:"validityDays,omitempty" tf:"validity_days,omitempty"`

	// (String) Identifier
	// Identifier
	ZoneID *string `json:"zoneId,omitempty" tf:"zone_id,omitempty"`
}

type PackObservation struct {

	// (String) Certificate Authority selected for the order.  For information on any certificate authority specific details or restrictions see this page for more details.
	// Certificate Authority selected for the order.  For information on any certificate authority specific details or restrictions [see this page for more details.](https://developers.cloudflare.com/ssl/reference/certificate-authorities)
	CertificateAuthority *string `json:"certificateAuthority,omitempty" tf:"certificate_authority,omitempty"`

	// (Boolean) Whether or not to add Cloudflare Branding for the order.  This will add a subdomain of sni.cloudflaressl.com as the Common Name if set to true.
	// Whether or not to add Cloudflare Branding for the order.  This will add a subdomain of sni.cloudflaressl.com as the Common Name if set to true.
	CloudflareBranding *bool `json:"cloudflareBranding,omitempty" tf:"cloudflare_branding,omitempty"`

	// (List of String) Comma separated list of valid host names for the certificate packs. Must contain the zone apex, may not contain more than 50 hosts, and may not be empty.
	// Comma separated list of valid host names for the certificate packs. Must contain the zone apex, may not contain more than 50 hosts, and may not be empty.
	Hosts []*string `json:"hosts,omitempty" tf:"hosts,omitempty"`

	// (String) Identifier
	ID *string `json:"id,omitempty" tf:"id,omitempty"`

	// (String) Status of certificate pack.
	// Status of certificate pack.
	Status *string `json:"status,omitempty" tf:"status,omitempty"`

	// (String) Type of certificate pack.
	// Type of certificate pack.
	Type *string `json:"type,omitempty" tf:"type,omitempty"`

	// (String) Validation Method selected for the order.
	// Validation Method selected for the order.
	ValidationMethod *string `json:"validationMethod,omitempty" tf:"validation_method,omitempty"`

	// (Number) Validity Days selected for the order.
	// Validity Days selected for the order.
	ValidityDays *float64 `json:"validityDays,omitempty" tf:"validity_days,omitempty"`

	// (String) Identifier
	// Identifier
	ZoneID *string `json:"zoneId,omitempty" tf:"zone_id,omitempty"`
}

type PackParameters struct {

	// (String) Certificate Authority selected for the order.  For information on any certificate authority specific details or restrictions see this page for more details.
	// Certificate Authority selected for the order.  For information on any certificate authority specific details or restrictions [see this page for more details.](https://developers.cloudflare.com/ssl/reference/certificate-authorities)
	// +kubebuilder:validation:Optional
	CertificateAuthority *string `json:"certificateAuthority,omitempty" tf:"certificate_authority,omitempty"`

	// (Boolean) Whether or not to add Cloudflare Branding for the order.  This will add a subdomain of sni.cloudflaressl.com as the Common Name if set to true.
	// Whether or not to add Cloudflare Branding for the order.  This will add a subdomain of sni.cloudflaressl.com as the Common Name if set to true.
	// +kubebuilder:validation:Optional
	CloudflareBranding *bool `json:"cloudflareBranding,omitempty" tf:"cloudflare_branding,omitempty"`

	// (List of String) Comma separated list of valid host names for the certificate packs. Must contain the zone apex, may not contain more than 50 hosts, and may not be empty.
	// Comma separated list of valid host names for the certificate packs. Must contain the zone apex, may not contain more than 50 hosts, and may not be empty.
	// +kubebuilder:validation:Optional
	Hosts []*string `json:"hosts,omitempty" tf:"hosts,omitempty"`

	// (String) Type of certificate pack.
	// Type of certificate pack.
	// +kubebuilder:validation:Optional
	Type *string `json:"type,omitempty" tf:"type,omitempty"`

	// (String) Validation Method selected for the order.
	// Validation Method selected for the order.
	// +kubebuilder:validation:Optional
	ValidationMethod *string `json:"validationMethod,omitempty" tf:"validation_method,omitempty"`

	// (Number) Validity Days selected for the order.
	// Validity Days selected for the order.
	// +kubebuilder:validation:Optional
	ValidityDays *float64 `json:"validityDays,omitempty" tf:"validity_days,omitempty"`

	// (String) Identifier
	// Identifier
	// +kubebuilder:validation:Optional
	ZoneID *string `json:"zoneId,omitempty" tf:"zone_id,omitempty"`
}

// PackSpec defines the desired state of Pack
type PackSpec struct {
	v1.ResourceSpec `json:",inline"`
	ForProvider     PackParameters `json:"forProvider"`
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
	InitProvider PackInitParameters `json:"initProvider,omitempty"`
}

// PackStatus defines the observed state of Pack.
type PackStatus struct {
	v1.ResourceStatus `json:",inline"`
	AtProvider        PackObservation `json:"atProvider,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:storageversion

// Pack is the Schema for the Packs API.
// +kubebuilder:printcolumn:name="SYNCED",type="string",JSONPath=".status.conditions[?(@.type=='Synced')].status"
// +kubebuilder:printcolumn:name="READY",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="EXTERNAL-NAME",type="string",JSONPath=".metadata.annotations.crossplane\\.io/external-name"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:resource:scope=Cluster,categories={crossplane,managed,cloudflare}
type Pack struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.certificateAuthority) || (has(self.initProvider) && has(self.initProvider.certificateAuthority))",message="spec.forProvider.certificateAuthority is a required parameter"
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.hosts) || (has(self.initProvider) && has(self.initProvider.hosts))",message="spec.forProvider.hosts is a required parameter"
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.type) || (has(self.initProvider) && has(self.initProvider.type))",message="spec.forProvider.type is a required parameter"
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.validationMethod) || (has(self.initProvider) && has(self.initProvider.validationMethod))",message="spec.forProvider.validationMethod is a required parameter"
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.validityDays) || (has(self.initProvider) && has(self.initProvider.validityDays))",message="spec.forProvider.validityDays is a required parameter"
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.zoneId) || (has(self.initProvider) && has(self.initProvider.zoneId))",message="spec.forProvider.zoneId is a required parameter"
	Spec   PackSpec   `json:"spec"`
	Status PackStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// PackList contains a list of Packs
type PackList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Pack `json:"items"`
}

// Repository type metadata.
var (
	Pack_Kind             = "Pack"
	Pack_GroupKind        = schema.GroupKind{Group: CRDGroup, Kind: Pack_Kind}.String()
	Pack_KindAPIVersion   = Pack_Kind + "." + CRDGroupVersion.String()
	Pack_GroupVersionKind = CRDGroupVersion.WithKind(Pack_Kind)
)

func init() {
	SchemeBuilder.Register(&Pack{}, &PackList{})
}
