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

type ConfigurationsInitParameters struct {

	// (String) The configuration target. You must set the target to ip when specifying an IP address in the Zone Lockdown rule.
	// The configuration target. You must set the target to `ip` when specifying an IP address in the Zone Lockdown rule.
	Target *string `json:"target,omitempty" tf:"target,omitempty"`

	// (String) The IP address to match. This address will be compared to the IP address of incoming requests.
	// The IP address to match. This address will be compared to the IP address of incoming requests.
	Value *string `json:"value,omitempty" tf:"value,omitempty"`
}

type ConfigurationsObservation struct {

	// (String) The configuration target. You must set the target to ip when specifying an IP address in the Zone Lockdown rule.
	// The configuration target. You must set the target to `ip` when specifying an IP address in the Zone Lockdown rule.
	Target *string `json:"target,omitempty" tf:"target,omitempty"`

	// (String) The IP address to match. This address will be compared to the IP address of incoming requests.
	// The IP address to match. This address will be compared to the IP address of incoming requests.
	Value *string `json:"value,omitempty" tf:"value,omitempty"`
}

type ConfigurationsParameters struct {

	// (String) The configuration target. You must set the target to ip when specifying an IP address in the Zone Lockdown rule.
	// The configuration target. You must set the target to `ip` when specifying an IP address in the Zone Lockdown rule.
	// +kubebuilder:validation:Optional
	Target *string `json:"target,omitempty" tf:"target,omitempty"`

	// (String) The IP address to match. This address will be compared to the IP address of incoming requests.
	// The IP address to match. This address will be compared to the IP address of incoming requests.
	// +kubebuilder:validation:Optional
	Value *string `json:"value,omitempty" tf:"value,omitempty"`
}

type LockdownInitParameters struct {

	// (Attributes List) A list of IP addresses or CIDR ranges that will be allowed to access the URLs specified in the Zone Lockdown rule. You can include any number of ip or ip_range configurations. (see below for nested schema)
	Configurations []ConfigurationsInitParameters `json:"configurations,omitempty" tf:"configurations,omitempty"`

	// (List of String) The URLs to include in the current WAF override. You can use wildcards. Each entered URL will be escaped before use, which means you can only use simple wildcard patterns.
	// The URLs to include in the current WAF override. You can use wildcards. Each entered URL will be escaped before use, which means you can only use simple wildcard patterns.
	Urls []*string `json:"urls,omitempty" tf:"urls,omitempty"`

	// (String) Identifier
	// Identifier
	ZoneID *string `json:"zoneId,omitempty" tf:"zone_id,omitempty"`
}

type LockdownObservation struct {

	// (Attributes List) A list of IP addresses or CIDR ranges that will be allowed to access the URLs specified in the Zone Lockdown rule. You can include any number of ip or ip_range configurations. (see below for nested schema)
	Configurations []ConfigurationsObservation `json:"configurations,omitempty" tf:"configurations,omitempty"`

	// (String) The timestamp of when the rule was created.
	// The timestamp of when the rule was created.
	CreatedOn *string `json:"createdOn,omitempty" tf:"created_on,omitempty"`

	// (String) An informative summary of the rule.
	// An informative summary of the rule.
	Description *string `json:"description,omitempty" tf:"description,omitempty"`

	// (String) The unique identifier of the Zone Lockdown rule.
	ID *string `json:"id,omitempty" tf:"id,omitempty"`

	// (String) The timestamp of when the rule was last modified.
	// The timestamp of when the rule was last modified.
	ModifiedOn *string `json:"modifiedOn,omitempty" tf:"modified_on,omitempty"`

	// (Boolean) When true, indicates that the rule is currently paused.
	// When true, indicates that the rule is currently paused.
	Paused *bool `json:"paused,omitempty" tf:"paused,omitempty"`

	// (List of String) The URLs to include in the current WAF override. You can use wildcards. Each entered URL will be escaped before use, which means you can only use simple wildcard patterns.
	// The URLs to include in the current WAF override. You can use wildcards. Each entered URL will be escaped before use, which means you can only use simple wildcard patterns.
	Urls []*string `json:"urls,omitempty" tf:"urls,omitempty"`

	// (String) Identifier
	// Identifier
	ZoneID *string `json:"zoneId,omitempty" tf:"zone_id,omitempty"`
}

type LockdownParameters struct {

	// (Attributes List) A list of IP addresses or CIDR ranges that will be allowed to access the URLs specified in the Zone Lockdown rule. You can include any number of ip or ip_range configurations. (see below for nested schema)
	// +kubebuilder:validation:Optional
	Configurations []ConfigurationsParameters `json:"configurations,omitempty" tf:"configurations,omitempty"`

	// (List of String) The URLs to include in the current WAF override. You can use wildcards. Each entered URL will be escaped before use, which means you can only use simple wildcard patterns.
	// The URLs to include in the current WAF override. You can use wildcards. Each entered URL will be escaped before use, which means you can only use simple wildcard patterns.
	// +kubebuilder:validation:Optional
	Urls []*string `json:"urls,omitempty" tf:"urls,omitempty"`

	// (String) Identifier
	// Identifier
	// +kubebuilder:validation:Optional
	ZoneID *string `json:"zoneId,omitempty" tf:"zone_id,omitempty"`
}

// LockdownSpec defines the desired state of Lockdown
type LockdownSpec struct {
	v1.ResourceSpec `json:",inline"`
	ForProvider     LockdownParameters `json:"forProvider"`
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
	InitProvider LockdownInitParameters `json:"initProvider,omitempty"`
}

// LockdownStatus defines the observed state of Lockdown.
type LockdownStatus struct {
	v1.ResourceStatus `json:",inline"`
	AtProvider        LockdownObservation `json:"atProvider,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:storageversion

// Lockdown is the Schema for the Lockdowns API.
// +kubebuilder:printcolumn:name="SYNCED",type="string",JSONPath=".status.conditions[?(@.type=='Synced')].status"
// +kubebuilder:printcolumn:name="READY",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="EXTERNAL-NAME",type="string",JSONPath=".metadata.annotations.crossplane\\.io/external-name"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:resource:scope=Cluster,categories={crossplane,managed,cloudflare-upjet}
type Lockdown struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.configurations) || (has(self.initProvider) && has(self.initProvider.configurations))",message="spec.forProvider.configurations is a required parameter"
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.urls) || (has(self.initProvider) && has(self.initProvider.urls))",message="spec.forProvider.urls is a required parameter"
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.zoneId) || (has(self.initProvider) && has(self.initProvider.zoneId))",message="spec.forProvider.zoneId is a required parameter"
	Spec   LockdownSpec   `json:"spec"`
	Status LockdownStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// LockdownList contains a list of Lockdowns
type LockdownList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Lockdown `json:"items"`
}

// Repository type metadata.
var (
	Lockdown_Kind             = "Lockdown"
	Lockdown_GroupKind        = schema.GroupKind{Group: CRDGroup, Kind: Lockdown_Kind}.String()
	Lockdown_KindAPIVersion   = Lockdown_Kind + "." + CRDGroupVersion.String()
	Lockdown_GroupVersionKind = CRDGroupVersion.WithKind(Lockdown_Kind)
)

func init() {
	SchemeBuilder.Register(&Lockdown{}, &LockdownList{})
}
