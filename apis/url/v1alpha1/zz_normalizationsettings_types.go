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

type NormalizationSettingsInitParameters struct {

	// (String) The scope of the URL normalization.
	// The scope of the URL normalization.
	Scope *string `json:"scope,omitempty" tf:"scope,omitempty"`

	// (String) The type of URL normalization performed by Cloudflare.
	// The type of URL normalization performed by Cloudflare.
	Type *string `json:"type,omitempty" tf:"type,omitempty"`

	// (String) The unique ID of the zone.
	// The unique ID of the zone.
	ZoneID *string `json:"zoneId,omitempty" tf:"zone_id,omitempty"`
}

type NormalizationSettingsObservation struct {

	// (String) The unique ID of the zone.
	ID *string `json:"id,omitempty" tf:"id,omitempty"`

	// (String) The scope of the URL normalization.
	// The scope of the URL normalization.
	Scope *string `json:"scope,omitempty" tf:"scope,omitempty"`

	// (String) The type of URL normalization performed by Cloudflare.
	// The type of URL normalization performed by Cloudflare.
	Type *string `json:"type,omitempty" tf:"type,omitempty"`

	// (String) The unique ID of the zone.
	// The unique ID of the zone.
	ZoneID *string `json:"zoneId,omitempty" tf:"zone_id,omitempty"`
}

type NormalizationSettingsParameters struct {

	// (String) The scope of the URL normalization.
	// The scope of the URL normalization.
	// +kubebuilder:validation:Optional
	Scope *string `json:"scope,omitempty" tf:"scope,omitempty"`

	// (String) The type of URL normalization performed by Cloudflare.
	// The type of URL normalization performed by Cloudflare.
	// +kubebuilder:validation:Optional
	Type *string `json:"type,omitempty" tf:"type,omitempty"`

	// (String) The unique ID of the zone.
	// The unique ID of the zone.
	// +kubebuilder:validation:Optional
	ZoneID *string `json:"zoneId,omitempty" tf:"zone_id,omitempty"`
}

// NormalizationSettingsSpec defines the desired state of NormalizationSettings
type NormalizationSettingsSpec struct {
	v1.ResourceSpec `json:",inline"`
	ForProvider     NormalizationSettingsParameters `json:"forProvider"`
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
	InitProvider NormalizationSettingsInitParameters `json:"initProvider,omitempty"`
}

// NormalizationSettingsStatus defines the observed state of NormalizationSettings.
type NormalizationSettingsStatus struct {
	v1.ResourceStatus `json:",inline"`
	AtProvider        NormalizationSettingsObservation `json:"atProvider,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:storageversion

// NormalizationSettings is the Schema for the NormalizationSettingss API.
// +kubebuilder:printcolumn:name="SYNCED",type="string",JSONPath=".status.conditions[?(@.type=='Synced')].status"
// +kubebuilder:printcolumn:name="READY",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="EXTERNAL-NAME",type="string",JSONPath=".metadata.annotations.crossplane\\.io/external-name"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:resource:scope=Cluster,categories={crossplane,managed,cloudflare}
type NormalizationSettings struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.scope) || (has(self.initProvider) && has(self.initProvider.scope))",message="spec.forProvider.scope is a required parameter"
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.type) || (has(self.initProvider) && has(self.initProvider.type))",message="spec.forProvider.type is a required parameter"
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.zoneId) || (has(self.initProvider) && has(self.initProvider.zoneId))",message="spec.forProvider.zoneId is a required parameter"
	Spec   NormalizationSettingsSpec   `json:"spec"`
	Status NormalizationSettingsStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// NormalizationSettingsList contains a list of NormalizationSettingss
type NormalizationSettingsList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []NormalizationSettings `json:"items"`
}

// Repository type metadata.
var (
	NormalizationSettings_Kind             = "NormalizationSettings"
	NormalizationSettings_GroupKind        = schema.GroupKind{Group: CRDGroup, Kind: NormalizationSettings_Kind}.String()
	NormalizationSettings_KindAPIVersion   = NormalizationSettings_Kind + "." + CRDGroupVersion.String()
	NormalizationSettings_GroupVersionKind = CRDGroupVersion.WithKind(NormalizationSettings_Kind)
)

func init() {
	SchemeBuilder.Register(&NormalizationSettings{}, &NormalizationSettingsList{})
}
