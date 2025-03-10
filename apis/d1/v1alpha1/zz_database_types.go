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

type DatabaseInitParameters struct {

	// (String) Account identifier tag.
	// Account identifier tag.
	AccountID *string `json:"accountId,omitempty" tf:"account_id,omitempty"`

	// (String) Specify the region to create the D1 primary, if available. If this option is omitted, the D1 will be created as close as possible to the current user.
	// Specify the region to create the D1 primary, if available. If this option is omitted, the D1 will be created as close as possible to the current user.
	PrimaryLocationHint *string `json:"primaryLocationHint,omitempty" tf:"primary_location_hint,omitempty"`
}

type DatabaseObservation struct {

	// (String) Account identifier tag.
	// Account identifier tag.
	AccountID *string `json:"accountId,omitempty" tf:"account_id,omitempty"`

	// (String) Specifies the timestamp the resource was created as an ISO8601 string.
	// Specifies the timestamp the resource was created as an ISO8601 string.
	CreatedAt *string `json:"createdAt,omitempty" tf:"created_at,omitempty"`

	// (Number) The D1 database's size, in bytes.
	// The D1 database's size, in bytes.
	FileSize *float64 `json:"fileSize,omitempty" tf:"file_size,omitempty"`

	// (String) D1 database identifier (UUID).
	ID *string `json:"id,omitempty" tf:"id,omitempty"`

	// (Number)
	NumTables *float64 `json:"numTables,omitempty" tf:"num_tables,omitempty"`

	// (String) Specify the region to create the D1 primary, if available. If this option is omitted, the D1 will be created as close as possible to the current user.
	// Specify the region to create the D1 primary, if available. If this option is omitted, the D1 will be created as close as possible to the current user.
	PrimaryLocationHint *string `json:"primaryLocationHint,omitempty" tf:"primary_location_hint,omitempty"`

	// (String) D1 database identifier (UUID).
	// D1 database identifier (UUID).
	UUID *string `json:"uuid,omitempty" tf:"uuid,omitempty"`

	// (String)
	Version *string `json:"version,omitempty" tf:"version,omitempty"`
}

type DatabaseParameters struct {

	// (String) Account identifier tag.
	// Account identifier tag.
	// +kubebuilder:validation:Optional
	AccountID *string `json:"accountId,omitempty" tf:"account_id,omitempty"`

	// (String) Specify the region to create the D1 primary, if available. If this option is omitted, the D1 will be created as close as possible to the current user.
	// Specify the region to create the D1 primary, if available. If this option is omitted, the D1 will be created as close as possible to the current user.
	// +kubebuilder:validation:Optional
	PrimaryLocationHint *string `json:"primaryLocationHint,omitempty" tf:"primary_location_hint,omitempty"`
}

// DatabaseSpec defines the desired state of Database
type DatabaseSpec struct {
	v1.ResourceSpec `json:",inline"`
	ForProvider     DatabaseParameters `json:"forProvider"`
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
	InitProvider DatabaseInitParameters `json:"initProvider,omitempty"`
}

// DatabaseStatus defines the observed state of Database.
type DatabaseStatus struct {
	v1.ResourceStatus `json:",inline"`
	AtProvider        DatabaseObservation `json:"atProvider,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:storageversion

// Database is the Schema for the Databases API.
// +kubebuilder:printcolumn:name="SYNCED",type="string",JSONPath=".status.conditions[?(@.type=='Synced')].status"
// +kubebuilder:printcolumn:name="READY",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="EXTERNAL-NAME",type="string",JSONPath=".metadata.annotations.crossplane\\.io/external-name"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:resource:scope=Cluster,categories={crossplane,managed,cloudflare-upjet}
type Database struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.accountId) || (has(self.initProvider) && has(self.initProvider.accountId))",message="spec.forProvider.accountId is a required parameter"
	Spec   DatabaseSpec   `json:"spec"`
	Status DatabaseStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// DatabaseList contains a list of Databases
type DatabaseList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Database `json:"items"`
}

// Repository type metadata.
var (
	Database_Kind             = "Database"
	Database_GroupKind        = schema.GroupKind{Group: CRDGroup, Kind: Database_Kind}.String()
	Database_KindAPIVersion   = Database_Kind + "." + CRDGroupVersion.String()
	Database_GroupVersionKind = CRDGroupVersion.WithKind(Database_Kind)
)

func init() {
	SchemeBuilder.Register(&Database{}, &DatabaseList{})
}
