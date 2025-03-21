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

type ShieldSchemaValidationSettingsInitParameters struct {

	// (String) The default mitigation action used when there is no mitigation action defined on the operation
	// The default mitigation action used when there is no mitigation action defined on the operation
	//
	// Mitigation actions are as follows:
	//
	// * `log` - log request when request does not conform to schema
	// * `block` - deny access to the site when request does not conform to schema
	//
	// A special value of of `none` will skip running schema validation entirely for the request when there is no mitigation action defined on the operation
	ValidationDefaultMitigationAction *string `json:"validationDefaultMitigationAction,omitempty" tf:"validation_default_mitigation_action,omitempty"`

	// (String) When set, this overrides both zone level and operation level mitigation actions.
	// When set, this overrides both zone level and operation level mitigation actions.
	//
	// - `none` will skip running schema validation entirely for the request
	// - `null` indicates that no override is in place
	//
	// To clear any override, use the special value `disable_override` or `null`
	ValidationOverrideMitigationAction *string `json:"validationOverrideMitigationAction,omitempty" tf:"validation_override_mitigation_action,omitempty"`

	// (String) Identifier
	// Identifier
	ZoneID *string `json:"zoneId,omitempty" tf:"zone_id,omitempty"`
}

type ShieldSchemaValidationSettingsObservation struct {

	// (String) Identifier
	ID *string `json:"id,omitempty" tf:"id,omitempty"`

	// (String) The default mitigation action used when there is no mitigation action defined on the operation
	// The default mitigation action used when there is no mitigation action defined on the operation
	//
	// Mitigation actions are as follows:
	//
	// * `log` - log request when request does not conform to schema
	// * `block` - deny access to the site when request does not conform to schema
	//
	// A special value of of `none` will skip running schema validation entirely for the request when there is no mitigation action defined on the operation
	ValidationDefaultMitigationAction *string `json:"validationDefaultMitigationAction,omitempty" tf:"validation_default_mitigation_action,omitempty"`

	// (String) When set, this overrides both zone level and operation level mitigation actions.
	// When set, this overrides both zone level and operation level mitigation actions.
	//
	// - `none` will skip running schema validation entirely for the request
	// - `null` indicates that no override is in place
	//
	// To clear any override, use the special value `disable_override` or `null`
	ValidationOverrideMitigationAction *string `json:"validationOverrideMitigationAction,omitempty" tf:"validation_override_mitigation_action,omitempty"`

	// (String) Identifier
	// Identifier
	ZoneID *string `json:"zoneId,omitempty" tf:"zone_id,omitempty"`
}

type ShieldSchemaValidationSettingsParameters struct {

	// (String) The default mitigation action used when there is no mitigation action defined on the operation
	// The default mitigation action used when there is no mitigation action defined on the operation
	//
	// Mitigation actions are as follows:
	//
	// * `log` - log request when request does not conform to schema
	// * `block` - deny access to the site when request does not conform to schema
	//
	// A special value of of `none` will skip running schema validation entirely for the request when there is no mitigation action defined on the operation
	// +kubebuilder:validation:Optional
	ValidationDefaultMitigationAction *string `json:"validationDefaultMitigationAction,omitempty" tf:"validation_default_mitigation_action,omitempty"`

	// (String) When set, this overrides both zone level and operation level mitigation actions.
	// When set, this overrides both zone level and operation level mitigation actions.
	//
	// - `none` will skip running schema validation entirely for the request
	// - `null` indicates that no override is in place
	//
	// To clear any override, use the special value `disable_override` or `null`
	// +kubebuilder:validation:Optional
	ValidationOverrideMitigationAction *string `json:"validationOverrideMitigationAction,omitempty" tf:"validation_override_mitigation_action,omitempty"`

	// (String) Identifier
	// Identifier
	// +kubebuilder:validation:Optional
	ZoneID *string `json:"zoneId,omitempty" tf:"zone_id,omitempty"`
}

// ShieldSchemaValidationSettingsSpec defines the desired state of ShieldSchemaValidationSettings
type ShieldSchemaValidationSettingsSpec struct {
	v1.ResourceSpec `json:",inline"`
	ForProvider     ShieldSchemaValidationSettingsParameters `json:"forProvider"`
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
	InitProvider ShieldSchemaValidationSettingsInitParameters `json:"initProvider,omitempty"`
}

// ShieldSchemaValidationSettingsStatus defines the observed state of ShieldSchemaValidationSettings.
type ShieldSchemaValidationSettingsStatus struct {
	v1.ResourceStatus `json:",inline"`
	AtProvider        ShieldSchemaValidationSettingsObservation `json:"atProvider,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:storageversion

// ShieldSchemaValidationSettings is the Schema for the ShieldSchemaValidationSettingss API.
// +kubebuilder:printcolumn:name="SYNCED",type="string",JSONPath=".status.conditions[?(@.type=='Synced')].status"
// +kubebuilder:printcolumn:name="READY",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="EXTERNAL-NAME",type="string",JSONPath=".metadata.annotations.crossplane\\.io/external-name"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:resource:scope=Cluster,categories={crossplane,managed,cloudflare}
type ShieldSchemaValidationSettings struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.validationDefaultMitigationAction) || (has(self.initProvider) && has(self.initProvider.validationDefaultMitigationAction))",message="spec.forProvider.validationDefaultMitigationAction is a required parameter"
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.zoneId) || (has(self.initProvider) && has(self.initProvider.zoneId))",message="spec.forProvider.zoneId is a required parameter"
	Spec   ShieldSchemaValidationSettingsSpec   `json:"spec"`
	Status ShieldSchemaValidationSettingsStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// ShieldSchemaValidationSettingsList contains a list of ShieldSchemaValidationSettingss
type ShieldSchemaValidationSettingsList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ShieldSchemaValidationSettings `json:"items"`
}

// Repository type metadata.
var (
	ShieldSchemaValidationSettings_Kind             = "ShieldSchemaValidationSettings"
	ShieldSchemaValidationSettings_GroupKind        = schema.GroupKind{Group: CRDGroup, Kind: ShieldSchemaValidationSettings_Kind}.String()
	ShieldSchemaValidationSettings_KindAPIVersion   = ShieldSchemaValidationSettings_Kind + "." + CRDGroupVersion.String()
	ShieldSchemaValidationSettings_GroupVersionKind = CRDGroupVersion.WithKind(ShieldSchemaValidationSettings_Kind)
)

func init() {
	SchemeBuilder.Register(&ShieldSchemaValidationSettings{}, &ShieldSchemaValidationSettingsList{})
}
