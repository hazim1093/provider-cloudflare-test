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

type ConfigInitParameters struct {

	// (String) Identifier
	// Certificate identifier tag.
	CertID *string `json:"certId,omitempty" tf:"cert_id,omitempty"`

	// level authenticated origin pulls is enabled. A null value voids the association.
	// Indicates whether hostname-level authenticated origin pulls is enabled. A null value voids the association.
	Enabled *bool `json:"enabled,omitempty" tf:"enabled,omitempty"`

	// (String) The hostname on the origin for which the client certificate uploaded will be used.
	// The hostname on the origin for which the client certificate uploaded will be used.
	Hostname *string `json:"hostname,omitempty" tf:"hostname,omitempty"`
}

type ConfigObservation struct {

	// (String) Identifier
	// Certificate identifier tag.
	CertID *string `json:"certId,omitempty" tf:"cert_id,omitempty"`

	// level authenticated origin pulls is enabled. A null value voids the association.
	// Indicates whether hostname-level authenticated origin pulls is enabled. A null value voids the association.
	Enabled *bool `json:"enabled,omitempty" tf:"enabled,omitempty"`

	// (String) The hostname on the origin for which the client certificate uploaded will be used.
	// The hostname on the origin for which the client certificate uploaded will be used.
	Hostname *string `json:"hostname,omitempty" tf:"hostname,omitempty"`
}

type ConfigParameters struct {

	// (String) Identifier
	// Certificate identifier tag.
	// +kubebuilder:validation:Optional
	CertID *string `json:"certId,omitempty" tf:"cert_id,omitempty"`

	// level authenticated origin pulls is enabled. A null value voids the association.
	// Indicates whether hostname-level authenticated origin pulls is enabled. A null value voids the association.
	// +kubebuilder:validation:Optional
	Enabled *bool `json:"enabled,omitempty" tf:"enabled,omitempty"`

	// (String) The hostname on the origin for which the client certificate uploaded will be used.
	// The hostname on the origin for which the client certificate uploaded will be used.
	// +kubebuilder:validation:Optional
	Hostname *string `json:"hostname,omitempty" tf:"hostname,omitempty"`
}

type OriginPullsInitParameters struct {

	// (Attributes List) (see below for nested schema)
	Config []ConfigInitParameters `json:"config,omitempty" tf:"config,omitempty"`

	// (String) The hostname on the origin for which the client certificate uploaded will be used.
	// The hostname on the origin for which the client certificate uploaded will be used.
	Hostname *string `json:"hostname,omitempty" tf:"hostname,omitempty"`

	// (String) Identifier
	// Identifier
	ZoneID *string `json:"zoneId,omitempty" tf:"zone_id,omitempty"`
}

type OriginPullsObservation struct {

	// (String) Identifier
	// Identifier
	CertID *string `json:"certId,omitempty" tf:"cert_id,omitempty"`

	// (String) Status of the certificate or the association.
	// Status of the certificate or the association.
	CertStatus *string `json:"certStatus,omitempty" tf:"cert_status,omitempty"`

	// (String) The time when the certificate was updated.
	// The time when the certificate was updated.
	CertUpdatedAt *string `json:"certUpdatedAt,omitempty" tf:"cert_updated_at,omitempty"`

	// (String) The time when the certificate was uploaded.
	// The time when the certificate was uploaded.
	CertUploadedOn *string `json:"certUploadedOn,omitempty" tf:"cert_uploaded_on,omitempty"`

	// (String) The hostname certificate.
	// The hostname certificate.
	Certificate *string `json:"certificate,omitempty" tf:"certificate,omitempty"`

	// (Attributes List) (see below for nested schema)
	Config []ConfigObservation `json:"config,omitempty" tf:"config,omitempty"`

	// (String) The time when the certificate was created.
	// The time when the certificate was created.
	CreatedAt *string `json:"createdAt,omitempty" tf:"created_at,omitempty"`

	// level authenticated origin pulls is enabled. A null value voids the association.
	// Indicates whether hostname-level authenticated origin pulls is enabled. A null value voids the association.
	Enabled *bool `json:"enabled,omitempty" tf:"enabled,omitempty"`

	// (String) The date when the certificate expires.
	// The date when the certificate expires.
	ExpiresOn *string `json:"expiresOn,omitempty" tf:"expires_on,omitempty"`

	// (String) The hostname on the origin for which the client certificate uploaded will be used.
	// The hostname on the origin for which the client certificate uploaded will be used.
	Hostname *string `json:"hostname,omitempty" tf:"hostname,omitempty"`

	// (String) Identifier
	ID *string `json:"id,omitempty" tf:"id,omitempty"`

	// (String) The certificate authority that issued the certificate.
	// The certificate authority that issued the certificate.
	Issuer *string `json:"issuer,omitempty" tf:"issuer,omitempty"`

	// (String) The hostname certificate's private key.
	// The hostname certificate's private key.
	PrivateKey *string `json:"privateKey,omitempty" tf:"private_key,omitempty"`

	// (String) The serial number on the uploaded certificate.
	// The serial number on the uploaded certificate.
	SerialNumber *string `json:"serialNumber,omitempty" tf:"serial_number,omitempty"`

	// (String) The type of hash used for the certificate.
	// The type of hash used for the certificate.
	Signature *string `json:"signature,omitempty" tf:"signature,omitempty"`

	// (String) Status of the certificate or the association.
	// Status of the certificate or the association.
	Status *string `json:"status,omitempty" tf:"status,omitempty"`

	// (String) The time when the certificate was updated.
	// The time when the certificate was updated.
	UpdatedAt *string `json:"updatedAt,omitempty" tf:"updated_at,omitempty"`

	// (String) Identifier
	// Identifier
	ZoneID *string `json:"zoneId,omitempty" tf:"zone_id,omitempty"`
}

type OriginPullsParameters struct {

	// (Attributes List) (see below for nested schema)
	// +kubebuilder:validation:Optional
	Config []ConfigParameters `json:"config,omitempty" tf:"config,omitempty"`

	// (String) The hostname on the origin for which the client certificate uploaded will be used.
	// The hostname on the origin for which the client certificate uploaded will be used.
	// +kubebuilder:validation:Optional
	Hostname *string `json:"hostname,omitempty" tf:"hostname,omitempty"`

	// (String) Identifier
	// Identifier
	// +kubebuilder:validation:Optional
	ZoneID *string `json:"zoneId,omitempty" tf:"zone_id,omitempty"`
}

// OriginPullsSpec defines the desired state of OriginPulls
type OriginPullsSpec struct {
	v1.ResourceSpec `json:",inline"`
	ForProvider     OriginPullsParameters `json:"forProvider"`
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
	InitProvider OriginPullsInitParameters `json:"initProvider,omitempty"`
}

// OriginPullsStatus defines the observed state of OriginPulls.
type OriginPullsStatus struct {
	v1.ResourceStatus `json:",inline"`
	AtProvider        OriginPullsObservation `json:"atProvider,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:storageversion

// OriginPulls is the Schema for the OriginPullss API.
// +kubebuilder:printcolumn:name="SYNCED",type="string",JSONPath=".status.conditions[?(@.type=='Synced')].status"
// +kubebuilder:printcolumn:name="READY",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="EXTERNAL-NAME",type="string",JSONPath=".metadata.annotations.crossplane\\.io/external-name"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:resource:scope=Cluster,categories={crossplane,managed,cloudflare}
type OriginPulls struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.config) || (has(self.initProvider) && has(self.initProvider.config))",message="spec.forProvider.config is a required parameter"
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.zoneId) || (has(self.initProvider) && has(self.initProvider.zoneId))",message="spec.forProvider.zoneId is a required parameter"
	Spec   OriginPullsSpec   `json:"spec"`
	Status OriginPullsStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// OriginPullsList contains a list of OriginPullss
type OriginPullsList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []OriginPulls `json:"items"`
}

// Repository type metadata.
var (
	OriginPulls_Kind             = "OriginPulls"
	OriginPulls_GroupKind        = schema.GroupKind{Group: CRDGroup, Kind: OriginPulls_Kind}.String()
	OriginPulls_KindAPIVersion   = OriginPulls_Kind + "." + CRDGroupVersion.String()
	OriginPulls_GroupVersionKind = CRDGroupVersion.WithKind(OriginPulls_Kind)
)

func init() {
	SchemeBuilder.Register(&OriginPulls{}, &OriginPullsList{})
}
