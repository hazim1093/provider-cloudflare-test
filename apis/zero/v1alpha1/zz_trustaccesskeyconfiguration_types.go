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

type TrustAccessKeyConfigurationInitParameters struct {

	// (String) Identifier
	// Identifier
	AccountID *string `json:"accountId,omitempty" tf:"account_id,omitempty"`

	// (Number) The number of days between key rotations.
	// The number of days between key rotations.
	KeyRotationIntervalDays *float64 `json:"keyRotationIntervalDays,omitempty" tf:"key_rotation_interval_days,omitempty"`
}

type TrustAccessKeyConfigurationObservation struct {

	// (String) Identifier
	// Identifier
	AccountID *string `json:"accountId,omitempty" tf:"account_id,omitempty"`

	// (Number) The number of days until the next key rotation.
	// The number of days until the next key rotation.
	DaysUntilNextRotation *float64 `json:"daysUntilNextRotation,omitempty" tf:"days_until_next_rotation,omitempty"`

	// (String) Identifier
	ID *string `json:"id,omitempty" tf:"id,omitempty"`

	// (Number) The number of days between key rotations.
	// The number of days between key rotations.
	KeyRotationIntervalDays *float64 `json:"keyRotationIntervalDays,omitempty" tf:"key_rotation_interval_days,omitempty"`

	// (String) The timestamp of the previous key rotation.
	// The timestamp of the previous key rotation.
	LastKeyRotationAt *string `json:"lastKeyRotationAt,omitempty" tf:"last_key_rotation_at,omitempty"`
}

type TrustAccessKeyConfigurationParameters struct {

	// (String) Identifier
	// Identifier
	// +kubebuilder:validation:Optional
	AccountID *string `json:"accountId,omitempty" tf:"account_id,omitempty"`

	// (Number) The number of days between key rotations.
	// The number of days between key rotations.
	// +kubebuilder:validation:Optional
	KeyRotationIntervalDays *float64 `json:"keyRotationIntervalDays,omitempty" tf:"key_rotation_interval_days,omitempty"`
}

// TrustAccessKeyConfigurationSpec defines the desired state of TrustAccessKeyConfiguration
type TrustAccessKeyConfigurationSpec struct {
	v1.ResourceSpec `json:",inline"`
	ForProvider     TrustAccessKeyConfigurationParameters `json:"forProvider"`
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
	InitProvider TrustAccessKeyConfigurationInitParameters `json:"initProvider,omitempty"`
}

// TrustAccessKeyConfigurationStatus defines the observed state of TrustAccessKeyConfiguration.
type TrustAccessKeyConfigurationStatus struct {
	v1.ResourceStatus `json:",inline"`
	AtProvider        TrustAccessKeyConfigurationObservation `json:"atProvider,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:storageversion

// TrustAccessKeyConfiguration is the Schema for the TrustAccessKeyConfigurations API.
// +kubebuilder:printcolumn:name="SYNCED",type="string",JSONPath=".status.conditions[?(@.type=='Synced')].status"
// +kubebuilder:printcolumn:name="READY",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="EXTERNAL-NAME",type="string",JSONPath=".metadata.annotations.crossplane\\.io/external-name"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:resource:scope=Cluster,categories={crossplane,managed,cloudflare}
type TrustAccessKeyConfiguration struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.accountId) || (has(self.initProvider) && has(self.initProvider.accountId))",message="spec.forProvider.accountId is a required parameter"
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.keyRotationIntervalDays) || (has(self.initProvider) && has(self.initProvider.keyRotationIntervalDays))",message="spec.forProvider.keyRotationIntervalDays is a required parameter"
	Spec   TrustAccessKeyConfigurationSpec   `json:"spec"`
	Status TrustAccessKeyConfigurationStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// TrustAccessKeyConfigurationList contains a list of TrustAccessKeyConfigurations
type TrustAccessKeyConfigurationList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []TrustAccessKeyConfiguration `json:"items"`
}

// Repository type metadata.
var (
	TrustAccessKeyConfiguration_Kind             = "TrustAccessKeyConfiguration"
	TrustAccessKeyConfiguration_GroupKind        = schema.GroupKind{Group: CRDGroup, Kind: TrustAccessKeyConfiguration_Kind}.String()
	TrustAccessKeyConfiguration_KindAPIVersion   = TrustAccessKeyConfiguration_Kind + "." + CRDGroupVersion.String()
	TrustAccessKeyConfiguration_GroupVersionKind = CRDGroupVersion.WithKind(TrustAccessKeyConfiguration_Kind)
)

func init() {
	SchemeBuilder.Register(&TrustAccessKeyConfiguration{}, &TrustAccessKeyConfigurationList{})
}
