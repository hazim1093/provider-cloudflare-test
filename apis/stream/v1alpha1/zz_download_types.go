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

type DownloadInitParameters struct {

	// (String) Identifier
	// Identifier
	AccountID *string `json:"accountId,omitempty" tf:"account_id,omitempty"`

	// generated unique identifier for a media item.
	// A Cloudflare-generated unique identifier for a media item.
	Identifier *string `json:"identifier,omitempty" tf:"identifier,omitempty"`
}

type DownloadObservation struct {

	// (String) Identifier
	// Identifier
	AccountID *string `json:"accountId,omitempty" tf:"account_id,omitempty"`

	ID *string `json:"id,omitempty" tf:"id,omitempty"`

	// generated unique identifier for a media item.
	// A Cloudflare-generated unique identifier for a media item.
	Identifier *string `json:"identifier,omitempty" tf:"identifier,omitempty"`
}

type DownloadParameters struct {

	// (String) Identifier
	// Identifier
	// +kubebuilder:validation:Optional
	AccountID *string `json:"accountId,omitempty" tf:"account_id,omitempty"`

	// generated unique identifier for a media item.
	// A Cloudflare-generated unique identifier for a media item.
	// +kubebuilder:validation:Optional
	Identifier *string `json:"identifier,omitempty" tf:"identifier,omitempty"`
}

// DownloadSpec defines the desired state of Download
type DownloadSpec struct {
	v1.ResourceSpec `json:",inline"`
	ForProvider     DownloadParameters `json:"forProvider"`
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
	InitProvider DownloadInitParameters `json:"initProvider,omitempty"`
}

// DownloadStatus defines the observed state of Download.
type DownloadStatus struct {
	v1.ResourceStatus `json:",inline"`
	AtProvider        DownloadObservation `json:"atProvider,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:storageversion

// Download is the Schema for the Downloads API.
// +kubebuilder:printcolumn:name="SYNCED",type="string",JSONPath=".status.conditions[?(@.type=='Synced')].status"
// +kubebuilder:printcolumn:name="READY",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="EXTERNAL-NAME",type="string",JSONPath=".metadata.annotations.crossplane\\.io/external-name"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:resource:scope=Cluster,categories={crossplane,managed,cloudflare}
type Download struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.accountId) || (has(self.initProvider) && has(self.initProvider.accountId))",message="spec.forProvider.accountId is a required parameter"
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.identifier) || (has(self.initProvider) && has(self.initProvider.identifier))",message="spec.forProvider.identifier is a required parameter"
	Spec   DownloadSpec   `json:"spec"`
	Status DownloadStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// DownloadList contains a list of Downloads
type DownloadList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Download `json:"items"`
}

// Repository type metadata.
var (
	Download_Kind             = "Download"
	Download_GroupKind        = schema.GroupKind{Group: CRDGroup, Kind: Download_Kind}.String()
	Download_KindAPIVersion   = Download_Kind + "." + CRDGroupVersion.String()
	Download_GroupVersionKind = CRDGroupVersion.WithKind(Download_Kind)
)

func init() {
	SchemeBuilder.Register(&Download{}, &DownloadList{})
}
