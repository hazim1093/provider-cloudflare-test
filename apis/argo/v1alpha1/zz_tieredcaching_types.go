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

type TieredCachingInitParameters struct {

	// (String) Enables Tiered Caching.
	// Enables Tiered Caching.
	Value *string `json:"value,omitempty" tf:"value,omitempty"`

	// (String) Identifier
	// Identifier
	ZoneID *string `json:"zoneId,omitempty" tf:"zone_id,omitempty"`
}

type TieredCachingObservation struct {

	// (Boolean) Whether the setting is editable
	// Whether the setting is editable
	Editable *bool `json:"editable,omitempty" tf:"editable,omitempty"`

	// (String) Identifier
	ID *string `json:"id,omitempty" tf:"id,omitempty"`

	// (String) Last time this setting was modified.
	// Last time this setting was modified.
	ModifiedOn *string `json:"modifiedOn,omitempty" tf:"modified_on,omitempty"`

	// (String) Enables Tiered Caching.
	// Enables Tiered Caching.
	Value *string `json:"value,omitempty" tf:"value,omitempty"`

	// (String) Identifier
	// Identifier
	ZoneID *string `json:"zoneId,omitempty" tf:"zone_id,omitempty"`
}

type TieredCachingParameters struct {

	// (String) Enables Tiered Caching.
	// Enables Tiered Caching.
	// +kubebuilder:validation:Optional
	Value *string `json:"value,omitempty" tf:"value,omitempty"`

	// (String) Identifier
	// Identifier
	// +kubebuilder:validation:Optional
	ZoneID *string `json:"zoneId,omitempty" tf:"zone_id,omitempty"`
}

// TieredCachingSpec defines the desired state of TieredCaching
type TieredCachingSpec struct {
	v1.ResourceSpec `json:",inline"`
	ForProvider     TieredCachingParameters `json:"forProvider"`
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
	InitProvider TieredCachingInitParameters `json:"initProvider,omitempty"`
}

// TieredCachingStatus defines the observed state of TieredCaching.
type TieredCachingStatus struct {
	v1.ResourceStatus `json:",inline"`
	AtProvider        TieredCachingObservation `json:"atProvider,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:storageversion

// TieredCaching is the Schema for the TieredCachings API.
// +kubebuilder:printcolumn:name="SYNCED",type="string",JSONPath=".status.conditions[?(@.type=='Synced')].status"
// +kubebuilder:printcolumn:name="READY",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="EXTERNAL-NAME",type="string",JSONPath=".metadata.annotations.crossplane\\.io/external-name"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:resource:scope=Cluster,categories={crossplane,managed,cloudflare-upjet}
type TieredCaching struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.value) || (has(self.initProvider) && has(self.initProvider.value))",message="spec.forProvider.value is a required parameter"
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.zoneId) || (has(self.initProvider) && has(self.initProvider.zoneId))",message="spec.forProvider.zoneId is a required parameter"
	Spec   TieredCachingSpec   `json:"spec"`
	Status TieredCachingStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// TieredCachingList contains a list of TieredCachings
type TieredCachingList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []TieredCaching `json:"items"`
}

// Repository type metadata.
var (
	TieredCaching_Kind             = "TieredCaching"
	TieredCaching_GroupKind        = schema.GroupKind{Group: CRDGroup, Kind: TieredCaching_Kind}.String()
	TieredCaching_KindAPIVersion   = TieredCaching_Kind + "." + CRDGroupVersion.String()
	TieredCaching_GroupVersionKind = CRDGroupVersion.WithKind(TieredCaching_Kind)
)

func init() {
	SchemeBuilder.Register(&TieredCaching{}, &TieredCachingList{})
}
