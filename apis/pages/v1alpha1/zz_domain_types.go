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

type DomainInitParameters struct {

	// (String) Identifier
	// Identifier
	AccountID *string `json:"accountId,omitempty" tf:"account_id,omitempty"`

	// (String) Name of the project.
	// Name of the project.
	ProjectName *string `json:"projectName,omitempty" tf:"project_name,omitempty"`

	// (Attributes) (see below for nested schema)
	ValidationData *ValidationDataInitParameters `json:"validationData,omitempty" tf:"validation_data,omitempty"`

	// (Attributes) (see below for nested schema)
	VerificationData *VerificationDataInitParameters `json:"verificationData,omitempty" tf:"verification_data,omitempty"`
}

type DomainObservation struct {

	// (String) Identifier
	// Identifier
	AccountID *string `json:"accountId,omitempty" tf:"account_id,omitempty"`

	// (String)
	CertificateAuthority *string `json:"certificateAuthority,omitempty" tf:"certificate_authority,omitempty"`

	// (String)
	CreatedOn *string `json:"createdOn,omitempty" tf:"created_on,omitempty"`

	// (String)
	DomainID *string `json:"domainId,omitempty" tf:"domain_id,omitempty"`

	// (String) The ID of this resource.
	ID *string `json:"id,omitempty" tf:"id,omitempty"`

	// (String) Name of the project.
	// Name of the project.
	ProjectName *string `json:"projectName,omitempty" tf:"project_name,omitempty"`

	// (String)
	Status *string `json:"status,omitempty" tf:"status,omitempty"`

	// (Attributes) (see below for nested schema)
	ValidationData *ValidationDataObservation `json:"validationData,omitempty" tf:"validation_data,omitempty"`

	// (Attributes) (see below for nested schema)
	VerificationData *VerificationDataObservation `json:"verificationData,omitempty" tf:"verification_data,omitempty"`

	// (String)
	ZoneTag *string `json:"zoneTag,omitempty" tf:"zone_tag,omitempty"`
}

type DomainParameters struct {

	// (String) Identifier
	// Identifier
	// +kubebuilder:validation:Optional
	AccountID *string `json:"accountId,omitempty" tf:"account_id,omitempty"`

	// (String) Name of the project.
	// Name of the project.
	// +kubebuilder:validation:Optional
	ProjectName *string `json:"projectName,omitempty" tf:"project_name,omitempty"`

	// (Attributes) (see below for nested schema)
	// +kubebuilder:validation:Optional
	ValidationData *ValidationDataParameters `json:"validationData,omitempty" tf:"validation_data,omitempty"`

	// (Attributes) (see below for nested schema)
	// +kubebuilder:validation:Optional
	VerificationData *VerificationDataParameters `json:"verificationData,omitempty" tf:"verification_data,omitempty"`
}

type ValidationDataInitParameters struct {
}

type ValidationDataObservation struct {

	// (String)
	ErrorMessage *string `json:"errorMessage,omitempty" tf:"error_message,omitempty"`

	// (String)
	Method *string `json:"method,omitempty" tf:"method,omitempty"`

	// (String)
	Status *string `json:"status,omitempty" tf:"status,omitempty"`

	// (String)
	TxtName *string `json:"txtName,omitempty" tf:"txt_name,omitempty"`

	// (String)
	TxtValue *string `json:"txtValue,omitempty" tf:"txt_value,omitempty"`
}

type ValidationDataParameters struct {
}

type VerificationDataInitParameters struct {
}

type VerificationDataObservation struct {

	// (String)
	ErrorMessage *string `json:"errorMessage,omitempty" tf:"error_message,omitempty"`

	// (String)
	Status *string `json:"status,omitempty" tf:"status,omitempty"`
}

type VerificationDataParameters struct {
}

// DomainSpec defines the desired state of Domain
type DomainSpec struct {
	v1.ResourceSpec `json:",inline"`
	ForProvider     DomainParameters `json:"forProvider"`
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
	InitProvider DomainInitParameters `json:"initProvider,omitempty"`
}

// DomainStatus defines the observed state of Domain.
type DomainStatus struct {
	v1.ResourceStatus `json:",inline"`
	AtProvider        DomainObservation `json:"atProvider,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:storageversion

// Domain is the Schema for the Domains API.
// +kubebuilder:printcolumn:name="SYNCED",type="string",JSONPath=".status.conditions[?(@.type=='Synced')].status"
// +kubebuilder:printcolumn:name="READY",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="EXTERNAL-NAME",type="string",JSONPath=".metadata.annotations.crossplane\\.io/external-name"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:resource:scope=Cluster,categories={crossplane,managed,cloudflare}
type Domain struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.accountId) || (has(self.initProvider) && has(self.initProvider.accountId))",message="spec.forProvider.accountId is a required parameter"
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.projectName) || (has(self.initProvider) && has(self.initProvider.projectName))",message="spec.forProvider.projectName is a required parameter"
	Spec   DomainSpec   `json:"spec"`
	Status DomainStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// DomainList contains a list of Domains
type DomainList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Domain `json:"items"`
}

// Repository type metadata.
var (
	Domain_Kind             = "Domain"
	Domain_GroupKind        = schema.GroupKind{Group: CRDGroup, Kind: Domain_Kind}.String()
	Domain_KindAPIVersion   = Domain_Kind + "." + CRDGroupVersion.String()
	Domain_GroupVersionKind = CRDGroupVersion.WithKind(Domain_Kind)
)

func init() {
	SchemeBuilder.Register(&Domain{}, &DomainList{})
}
