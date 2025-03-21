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

type OneRequestAssetInitParameters struct {

	// (String) Identifier
	// Identifier
	AccountIdentifier *string `json:"accountIdentifier,omitempty" tf:"account_identifier,omitempty"`

	// (Number) Page number of results
	// Page number of results
	Page *float64 `json:"page,omitempty" tf:"page,omitempty"`

	// (Number) Number of results per page
	// Number of results per page
	PerPage *float64 `json:"perPage,omitempty" tf:"per_page,omitempty"`

	// (String) UUID
	// UUID
	RequestIdentifier *string `json:"requestIdentifier,omitempty" tf:"request_identifier,omitempty"`

	// (String) Asset file to upload
	// Asset file to upload
	Source *string `json:"source,omitempty" tf:"source,omitempty"`
}

type OneRequestAssetObservation struct {

	// (String) Identifier
	// Identifier
	AccountIdentifier *string `json:"accountIdentifier,omitempty" tf:"account_identifier,omitempty"`

	// (String) Asset creation time
	// Asset creation time
	Created *string `json:"created,omitempty" tf:"created,omitempty"`

	// (String) Asset description
	// Asset description
	Description *string `json:"description,omitempty" tf:"description,omitempty"`

	// (String) Asset file type
	// Asset file type
	FileType *string `json:"fileType,omitempty" tf:"file_type,omitempty"`

	// (Number) Asset ID
	ID *string `json:"id,omitempty" tf:"id,omitempty"`

	// (Number) Page number of results
	// Page number of results
	Page *float64 `json:"page,omitempty" tf:"page,omitempty"`

	// (Number) Number of results per page
	// Number of results per page
	PerPage *float64 `json:"perPage,omitempty" tf:"per_page,omitempty"`

	// (String) UUID
	// UUID
	RequestIdentifier *string `json:"requestIdentifier,omitempty" tf:"request_identifier,omitempty"`

	// (String) Asset file to upload
	// Asset file to upload
	Source *string `json:"source,omitempty" tf:"source,omitempty"`
}

type OneRequestAssetParameters struct {

	// (String) Identifier
	// Identifier
	// +kubebuilder:validation:Optional
	AccountIdentifier *string `json:"accountIdentifier,omitempty" tf:"account_identifier,omitempty"`

	// (Number) Page number of results
	// Page number of results
	// +kubebuilder:validation:Optional
	Page *float64 `json:"page,omitempty" tf:"page,omitempty"`

	// (Number) Number of results per page
	// Number of results per page
	// +kubebuilder:validation:Optional
	PerPage *float64 `json:"perPage,omitempty" tf:"per_page,omitempty"`

	// (String) UUID
	// UUID
	// +kubebuilder:validation:Optional
	RequestIdentifier *string `json:"requestIdentifier,omitempty" tf:"request_identifier,omitempty"`

	// (String) Asset file to upload
	// Asset file to upload
	// +kubebuilder:validation:Optional
	Source *string `json:"source,omitempty" tf:"source,omitempty"`
}

// OneRequestAssetSpec defines the desired state of OneRequestAsset
type OneRequestAssetSpec struct {
	v1.ResourceSpec `json:",inline"`
	ForProvider     OneRequestAssetParameters `json:"forProvider"`
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
	InitProvider OneRequestAssetInitParameters `json:"initProvider,omitempty"`
}

// OneRequestAssetStatus defines the observed state of OneRequestAsset.
type OneRequestAssetStatus struct {
	v1.ResourceStatus `json:",inline"`
	AtProvider        OneRequestAssetObservation `json:"atProvider,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:storageversion

// OneRequestAsset is the Schema for the OneRequestAssets API.
// +kubebuilder:printcolumn:name="SYNCED",type="string",JSONPath=".status.conditions[?(@.type=='Synced')].status"
// +kubebuilder:printcolumn:name="READY",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="EXTERNAL-NAME",type="string",JSONPath=".metadata.annotations.crossplane\\.io/external-name"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:resource:scope=Cluster,categories={crossplane,managed,cloudflare}
type OneRequestAsset struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.accountIdentifier) || (has(self.initProvider) && has(self.initProvider.accountIdentifier))",message="spec.forProvider.accountIdentifier is a required parameter"
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.page) || (has(self.initProvider) && has(self.initProvider.page))",message="spec.forProvider.page is a required parameter"
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.perPage) || (has(self.initProvider) && has(self.initProvider.perPage))",message="spec.forProvider.perPage is a required parameter"
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.requestIdentifier) || (has(self.initProvider) && has(self.initProvider.requestIdentifier))",message="spec.forProvider.requestIdentifier is a required parameter"
	Spec   OneRequestAssetSpec   `json:"spec"`
	Status OneRequestAssetStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// OneRequestAssetList contains a list of OneRequestAssets
type OneRequestAssetList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []OneRequestAsset `json:"items"`
}

// Repository type metadata.
var (
	OneRequestAsset_Kind             = "OneRequestAsset"
	OneRequestAsset_GroupKind        = schema.GroupKind{Group: CRDGroup, Kind: OneRequestAsset_Kind}.String()
	OneRequestAsset_KindAPIVersion   = OneRequestAsset_Kind + "." + CRDGroupVersion.String()
	OneRequestAsset_GroupVersionKind = CRDGroupVersion.WithKind(OneRequestAsset_Kind)
)

func init() {
	SchemeBuilder.Register(&OneRequestAsset{}, &OneRequestAssetList{})
}
