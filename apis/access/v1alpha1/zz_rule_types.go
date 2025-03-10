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

type ConfigurationInitParameters struct {

	// (String) The configuration target. You must set the target to ip when specifying an IP address in the rule.
	// The configuration target. You must set the target to `ip` when specifying an IP address in the rule.
	Target *string `json:"target,omitempty" tf:"target,omitempty"`

	// (String) The IP address to match. This address will be compared to the IP address of incoming requests.
	// The IP address to match. This address will be compared to the IP address of incoming requests.
	Value *string `json:"value,omitempty" tf:"value,omitempty"`
}

type ConfigurationObservation struct {

	// (String) The configuration target. You must set the target to ip when specifying an IP address in the rule.
	// The configuration target. You must set the target to `ip` when specifying an IP address in the rule.
	Target *string `json:"target,omitempty" tf:"target,omitempty"`

	// (String) The IP address to match. This address will be compared to the IP address of incoming requests.
	// The IP address to match. This address will be compared to the IP address of incoming requests.
	Value *string `json:"value,omitempty" tf:"value,omitempty"`
}

type ConfigurationParameters struct {

	// (String) The configuration target. You must set the target to ip when specifying an IP address in the rule.
	// The configuration target. You must set the target to `ip` when specifying an IP address in the rule.
	// +kubebuilder:validation:Optional
	Target *string `json:"target,omitempty" tf:"target,omitempty"`

	// (String) The IP address to match. This address will be compared to the IP address of incoming requests.
	// The IP address to match. This address will be compared to the IP address of incoming requests.
	// +kubebuilder:validation:Optional
	Value *string `json:"value,omitempty" tf:"value,omitempty"`
}

type RuleInitParameters struct {

	// (String) The Account ID to use for this endpoint. Mutually exclusive with the Zone ID.
	// The Account ID to use for this endpoint. Mutually exclusive with the Zone ID.
	AccountID *string `json:"accountId,omitempty" tf:"account_id,omitempty"`

	// (Attributes) The rule configuration. (see below for nested schema)
	Configuration *ConfigurationInitParameters `json:"configuration,omitempty" tf:"configuration,omitempty"`

	// (String) The action to apply to a matched request.
	// The action to apply to a matched request.
	Mode *string `json:"mode,omitempty" tf:"mode,omitempty"`

	// (String) An informative summary of the rule, typically used as a reminder or explanation.
	// An informative summary of the rule, typically used as a reminder or explanation.
	Notes *string `json:"notes,omitempty" tf:"notes,omitempty"`

	// (Attributes) All zones owned by the user will have the rule applied. (see below for nested schema)
	Scope *ScopeInitParameters `json:"scope,omitempty" tf:"scope,omitempty"`

	// (String) The Zone ID to use for this endpoint. Mutually exclusive with the Account ID.
	// The Zone ID to use for this endpoint. Mutually exclusive with the Account ID.
	ZoneID *string `json:"zoneId,omitempty" tf:"zone_id,omitempty"`
}

type RuleObservation struct {

	// (String) The Account ID to use for this endpoint. Mutually exclusive with the Zone ID.
	// The Account ID to use for this endpoint. Mutually exclusive with the Zone ID.
	AccountID *string `json:"accountId,omitempty" tf:"account_id,omitempty"`

	// (List of String) The available actions that a rule can apply to a matched request.
	// The available actions that a rule can apply to a matched request.
	AllowedModes []*string `json:"allowedModes,omitempty" tf:"allowed_modes,omitempty"`

	// (Attributes) The rule configuration. (see below for nested schema)
	Configuration *ConfigurationObservation `json:"configuration,omitempty" tf:"configuration,omitempty"`

	// (String) The timestamp of when the rule was created.
	// The timestamp of when the rule was created.
	CreatedOn *string `json:"createdOn,omitempty" tf:"created_on,omitempty"`

	// (String) The unique identifier of the IP Access rule.
	ID *string `json:"id,omitempty" tf:"id,omitempty"`

	// (String) The action to apply to a matched request.
	// The action to apply to a matched request.
	Mode *string `json:"mode,omitempty" tf:"mode,omitempty"`

	// (String) The timestamp of when the rule was last modified.
	// The timestamp of when the rule was last modified.
	ModifiedOn *string `json:"modifiedOn,omitempty" tf:"modified_on,omitempty"`

	// (String) An informative summary of the rule, typically used as a reminder or explanation.
	// An informative summary of the rule, typically used as a reminder or explanation.
	Notes *string `json:"notes,omitempty" tf:"notes,omitempty"`

	// (Attributes) All zones owned by the user will have the rule applied. (see below for nested schema)
	Scope *ScopeObservation `json:"scope,omitempty" tf:"scope,omitempty"`

	// (String) The Zone ID to use for this endpoint. Mutually exclusive with the Account ID.
	// The Zone ID to use for this endpoint. Mutually exclusive with the Account ID.
	ZoneID *string `json:"zoneId,omitempty" tf:"zone_id,omitempty"`
}

type RuleParameters struct {

	// (String) The Account ID to use for this endpoint. Mutually exclusive with the Zone ID.
	// The Account ID to use for this endpoint. Mutually exclusive with the Zone ID.
	// +kubebuilder:validation:Optional
	AccountID *string `json:"accountId,omitempty" tf:"account_id,omitempty"`

	// (Attributes) The rule configuration. (see below for nested schema)
	// +kubebuilder:validation:Optional
	Configuration *ConfigurationParameters `json:"configuration,omitempty" tf:"configuration,omitempty"`

	// (String) The action to apply to a matched request.
	// The action to apply to a matched request.
	// +kubebuilder:validation:Optional
	Mode *string `json:"mode,omitempty" tf:"mode,omitempty"`

	// (String) An informative summary of the rule, typically used as a reminder or explanation.
	// An informative summary of the rule, typically used as a reminder or explanation.
	// +kubebuilder:validation:Optional
	Notes *string `json:"notes,omitempty" tf:"notes,omitempty"`

	// (Attributes) All zones owned by the user will have the rule applied. (see below for nested schema)
	// +kubebuilder:validation:Optional
	Scope *ScopeParameters `json:"scope,omitempty" tf:"scope,omitempty"`

	// (String) The Zone ID to use for this endpoint. Mutually exclusive with the Account ID.
	// The Zone ID to use for this endpoint. Mutually exclusive with the Account ID.
	// +kubebuilder:validation:Optional
	ZoneID *string `json:"zoneId,omitempty" tf:"zone_id,omitempty"`
}

type ScopeInitParameters struct {
}

type ScopeObservation struct {

	// (String) The contact email address of the user.
	// The contact email address of the user.
	Email *string `json:"email,omitempty" tf:"email,omitempty"`

	// (String) The unique identifier of the IP Access rule.
	// Identifier
	ID *string `json:"id,omitempty" tf:"id,omitempty"`

	// (String) The scope of the rule.
	// The scope of the rule.
	Type *string `json:"type,omitempty" tf:"type,omitempty"`
}

type ScopeParameters struct {
}

// RuleSpec defines the desired state of Rule
type RuleSpec struct {
	v1.ResourceSpec `json:",inline"`
	ForProvider     RuleParameters `json:"forProvider"`
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
	InitProvider RuleInitParameters `json:"initProvider,omitempty"`
}

// RuleStatus defines the observed state of Rule.
type RuleStatus struct {
	v1.ResourceStatus `json:",inline"`
	AtProvider        RuleObservation `json:"atProvider,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:storageversion

// Rule is the Schema for the Rules API.
// +kubebuilder:printcolumn:name="SYNCED",type="string",JSONPath=".status.conditions[?(@.type=='Synced')].status"
// +kubebuilder:printcolumn:name="READY",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="EXTERNAL-NAME",type="string",JSONPath=".metadata.annotations.crossplane\\.io/external-name"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:resource:scope=Cluster,categories={crossplane,managed,cloudflare}
type Rule struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.mode) || (has(self.initProvider) && has(self.initProvider.mode))",message="spec.forProvider.mode is a required parameter"
	Spec   RuleSpec   `json:"spec"`
	Status RuleStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// RuleList contains a list of Rules
type RuleList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Rule `json:"items"`
}

// Repository type metadata.
var (
	Rule_Kind             = "Rule"
	Rule_GroupKind        = schema.GroupKind{Group: CRDGroup, Kind: Rule_Kind}.String()
	Rule_KindAPIVersion   = Rule_Kind + "." + CRDGroupVersion.String()
	Rule_GroupVersionKind = CRDGroupVersion.WithKind(Rule_Kind)
)

func init() {
	SchemeBuilder.Register(&Rule{}, &RuleList{})
}
