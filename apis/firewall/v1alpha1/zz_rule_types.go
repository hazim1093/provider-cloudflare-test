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

type ActionInitParameters struct {

	// (String) The action to perform.
	// The action to perform.
	Mode *string `json:"mode,omitempty" tf:"mode,omitempty"`

	// (Attributes) A custom content type and reponse to return when the threshold is exceeded. The custom response configured in this object will override the custom error for the zone. This object is optional.
	// Notes: If you omit this object, Cloudflare will use the default HTML error page. If "mode" is "challenge", "managed_challenge", or "js_challenge", Cloudflare will use the zone challenge pages and you should not provide the "response" object. (see below for nested schema)
	Response *ResponseInitParameters `json:"response,omitempty" tf:"response,omitempty"`

	// (Number) The time in seconds during which Cloudflare will perform the mitigation action. Must be an integer value greater than or equal to the period.
	// Notes: If "mode" is "challenge", "managed_challenge", or "js_challenge", Cloudflare will use the zone's Challenge Passage time and you should not provide this value.
	// The time in seconds during which Cloudflare will perform the mitigation action. Must be an integer value greater than or equal to the period.
	// Notes: If "mode" is "challenge", "managed_challenge", or "js_challenge", Cloudflare will use the zone's Challenge Passage time and you should not provide this value.
	Timeout *float64 `json:"timeout,omitempty" tf:"timeout,omitempty"`
}

type ActionObservation struct {

	// (String) The action to perform.
	// The action to perform.
	Mode *string `json:"mode,omitempty" tf:"mode,omitempty"`

	// (Attributes) A custom content type and reponse to return when the threshold is exceeded. The custom response configured in this object will override the custom error for the zone. This object is optional.
	// Notes: If you omit this object, Cloudflare will use the default HTML error page. If "mode" is "challenge", "managed_challenge", or "js_challenge", Cloudflare will use the zone challenge pages and you should not provide the "response" object. (see below for nested schema)
	Response *ResponseObservation `json:"response,omitempty" tf:"response,omitempty"`

	// (Number) The time in seconds during which Cloudflare will perform the mitigation action. Must be an integer value greater than or equal to the period.
	// Notes: If "mode" is "challenge", "managed_challenge", or "js_challenge", Cloudflare will use the zone's Challenge Passage time and you should not provide this value.
	// The time in seconds during which Cloudflare will perform the mitigation action. Must be an integer value greater than or equal to the period.
	// Notes: If "mode" is "challenge", "managed_challenge", or "js_challenge", Cloudflare will use the zone's Challenge Passage time and you should not provide this value.
	Timeout *float64 `json:"timeout,omitempty" tf:"timeout,omitempty"`
}

type ActionParameters struct {

	// (String) The action to perform.
	// The action to perform.
	// +kubebuilder:validation:Optional
	Mode *string `json:"mode,omitempty" tf:"mode,omitempty"`

	// (Attributes) A custom content type and reponse to return when the threshold is exceeded. The custom response configured in this object will override the custom error for the zone. This object is optional.
	// Notes: If you omit this object, Cloudflare will use the default HTML error page. If "mode" is "challenge", "managed_challenge", or "js_challenge", Cloudflare will use the zone challenge pages and you should not provide the "response" object. (see below for nested schema)
	// +kubebuilder:validation:Optional
	Response *ResponseParameters `json:"response,omitempty" tf:"response,omitempty"`

	// (Number) The time in seconds during which Cloudflare will perform the mitigation action. Must be an integer value greater than or equal to the period.
	// Notes: If "mode" is "challenge", "managed_challenge", or "js_challenge", Cloudflare will use the zone's Challenge Passage time and you should not provide this value.
	// The time in seconds during which Cloudflare will perform the mitigation action. Must be an integer value greater than or equal to the period.
	// Notes: If "mode" is "challenge", "managed_challenge", or "js_challenge", Cloudflare will use the zone's Challenge Passage time and you should not provide this value.
	// +kubebuilder:validation:Optional
	Timeout *float64 `json:"timeout,omitempty" tf:"timeout,omitempty"`
}

type FilterInitParameters struct {

	// (String) An informative summary of the firewall rule.
	// An informative summary of the filter.
	Description *string `json:"description,omitempty" tf:"description,omitempty"`

	// (String) The filter expression. For more information, refer to Expressions.
	// The filter expression. For more information, refer to [Expressions](https://developers.cloudflare.com/ruleset-engine/rules-language/expressions/).
	Expression *string `json:"expression,omitempty" tf:"expression,omitempty"`

	// (Boolean) When true, indicates that the firewall rule is currently paused.
	// When true, indicates that the filter is currently paused.
	Paused *bool `json:"paused,omitempty" tf:"paused,omitempty"`

	// (String) A short reference tag. Allows you to select related firewall rules.
	// A short reference tag. Allows you to select related filters.
	Ref *string `json:"ref,omitempty" tf:"ref,omitempty"`
}

type FilterObservation struct {

	// (String) An informative summary of the firewall rule.
	// An informative summary of the filter.
	Description *string `json:"description,omitempty" tf:"description,omitempty"`

	// (String) The filter expression. For more information, refer to Expressions.
	// The filter expression. For more information, refer to [Expressions](https://developers.cloudflare.com/ruleset-engine/rules-language/expressions/).
	Expression *string `json:"expression,omitempty" tf:"expression,omitempty"`

	// (String) The unique identifier of the firewall rule.
	// The unique identifier of the filter.
	ID *string `json:"id,omitempty" tf:"id,omitempty"`

	// (Boolean) When true, indicates that the firewall rule is currently paused.
	// When true, indicates that the filter is currently paused.
	Paused *bool `json:"paused,omitempty" tf:"paused,omitempty"`

	// (String) A short reference tag. Allows you to select related firewall rules.
	// A short reference tag. Allows you to select related filters.
	Ref *string `json:"ref,omitempty" tf:"ref,omitempty"`
}

type FilterParameters struct {

	// (String) An informative summary of the firewall rule.
	// An informative summary of the filter.
	// +kubebuilder:validation:Optional
	Description *string `json:"description,omitempty" tf:"description,omitempty"`

	// (String) The filter expression. For more information, refer to Expressions.
	// The filter expression. For more information, refer to [Expressions](https://developers.cloudflare.com/ruleset-engine/rules-language/expressions/).
	// +kubebuilder:validation:Optional
	Expression *string `json:"expression,omitempty" tf:"expression,omitempty"`

	// (Boolean) When true, indicates that the firewall rule is currently paused.
	// When true, indicates that the filter is currently paused.
	// +kubebuilder:validation:Optional
	Paused *bool `json:"paused,omitempty" tf:"paused,omitempty"`

	// (String) A short reference tag. Allows you to select related firewall rules.
	// A short reference tag. Allows you to select related filters.
	// +kubebuilder:validation:Optional
	Ref *string `json:"ref,omitempty" tf:"ref,omitempty"`
}

type ResponseInitParameters struct {

	// (String) The response body to return. The value must conform to the configured content type.
	// The response body to return. The value must conform to the configured content type.
	Body *string `json:"body,omitempty" tf:"body,omitempty"`

	// (String) The content type of the body. Must be one of the following: text/plain, text/xml, or application/json.
	// The content type of the body. Must be one of the following: `text/plain`, `text/xml`, or `application/json`.
	ContentType *string `json:"contentType,omitempty" tf:"content_type,omitempty"`
}

type ResponseObservation struct {

	// (String) The response body to return. The value must conform to the configured content type.
	// The response body to return. The value must conform to the configured content type.
	Body *string `json:"body,omitempty" tf:"body,omitempty"`

	// (String) The content type of the body. Must be one of the following: text/plain, text/xml, or application/json.
	// The content type of the body. Must be one of the following: `text/plain`, `text/xml`, or `application/json`.
	ContentType *string `json:"contentType,omitempty" tf:"content_type,omitempty"`
}

type ResponseParameters struct {

	// (String) The response body to return. The value must conform to the configured content type.
	// The response body to return. The value must conform to the configured content type.
	// +kubebuilder:validation:Optional
	Body *string `json:"body,omitempty" tf:"body,omitempty"`

	// (String) The content type of the body. Must be one of the following: text/plain, text/xml, or application/json.
	// The content type of the body. Must be one of the following: `text/plain`, `text/xml`, or `application/json`.
	// +kubebuilder:validation:Optional
	ContentType *string `json:"contentType,omitempty" tf:"content_type,omitempty"`
}

type RuleInitParameters struct {

	// (Attributes) The action to perform when the threshold of matched traffic within the configured period is exceeded. (see below for nested schema)
	Action *ActionInitParameters `json:"action,omitempty" tf:"action,omitempty"`

	// (Attributes) (see below for nested schema)
	Filter *FilterInitParameters `json:"filter,omitempty" tf:"filter,omitempty"`

	// (String) Identifier
	// Identifier
	ZoneID *string `json:"zoneId,omitempty" tf:"zone_id,omitempty"`
}

type RuleObservation struct {

	// (Attributes) The action to perform when the threshold of matched traffic within the configured period is exceeded. (see below for nested schema)
	Action *ActionObservation `json:"action,omitempty" tf:"action,omitempty"`

	// (String) An informative summary of the firewall rule.
	// An informative summary of the firewall rule.
	Description *string `json:"description,omitempty" tf:"description,omitempty"`

	// (Attributes) (see below for nested schema)
	Filter *FilterObservation `json:"filter,omitempty" tf:"filter,omitempty"`

	// (String) The unique identifier of the firewall rule.
	ID *string `json:"id,omitempty" tf:"id,omitempty"`

	// (Boolean) When true, indicates that the firewall rule is currently paused.
	// When true, indicates that the firewall rule is currently paused.
	Paused *bool `json:"paused,omitempty" tf:"paused,omitempty"`

	// (Number) The priority of the rule. Optional value used to define the processing order. A lower number indicates a higher priority. If not provided, rules with a defined priority will be processed before rules without a priority.
	// The priority of the rule. Optional value used to define the processing order. A lower number indicates a higher priority. If not provided, rules with a defined priority will be processed before rules without a priority.
	Priority *float64 `json:"priority,omitempty" tf:"priority,omitempty"`

	// (List of String)
	Products []*string `json:"products,omitempty" tf:"products,omitempty"`

	// (String) A short reference tag. Allows you to select related firewall rules.
	// A short reference tag. Allows you to select related firewall rules.
	Ref *string `json:"ref,omitempty" tf:"ref,omitempty"`

	// (String) Identifier
	// Identifier
	ZoneID *string `json:"zoneId,omitempty" tf:"zone_id,omitempty"`
}

type RuleParameters struct {

	// (Attributes) The action to perform when the threshold of matched traffic within the configured period is exceeded. (see below for nested schema)
	// +kubebuilder:validation:Optional
	Action *ActionParameters `json:"action,omitempty" tf:"action,omitempty"`

	// (Attributes) (see below for nested schema)
	// +kubebuilder:validation:Optional
	Filter *FilterParameters `json:"filter,omitempty" tf:"filter,omitempty"`

	// (String) Identifier
	// Identifier
	// +kubebuilder:validation:Optional
	ZoneID *string `json:"zoneId,omitempty" tf:"zone_id,omitempty"`
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
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.zoneId) || (has(self.initProvider) && has(self.initProvider.zoneId))",message="spec.forProvider.zoneId is a required parameter"
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
