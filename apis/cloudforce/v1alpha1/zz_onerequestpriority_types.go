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

type OneRequestPriorityInitParameters struct {

	// (String) Identifier
	// Identifier
	AccountIdentifier *string `json:"accountIdentifier,omitempty" tf:"account_identifier,omitempty"`

	// (List of String) List of labels
	// List of labels
	Labels []*string `json:"labels,omitempty" tf:"labels,omitempty"`

	// (Number) Priority
	// Priority
	Priority *float64 `json:"priority,omitempty" tf:"priority,omitempty"`

	// (String) Requirement
	// Requirement
	Requirement *string `json:"requirement,omitempty" tf:"requirement,omitempty"`

	// (String) The CISA defined Traffic Light Protocol (TLP)
	// The CISA defined Traffic Light Protocol (TLP)
	Tlp *string `json:"tlp,omitempty" tf:"tlp,omitempty"`
}

type OneRequestPriorityObservation struct {

	// (String) Identifier
	// Identifier
	AccountIdentifier *string `json:"accountIdentifier,omitempty" tf:"account_identifier,omitempty"`

	// (String)
	Completed *string `json:"completed,omitempty" tf:"completed,omitempty"`

	// (String) Request content
	// Request content
	Content *string `json:"content,omitempty" tf:"content,omitempty"`

	// (String)
	Created *string `json:"created,omitempty" tf:"created,omitempty"`

	// (String) UUID
	ID *string `json:"id,omitempty" tf:"id,omitempty"`

	// (List of String) List of labels
	// List of labels
	Labels []*string `json:"labels,omitempty" tf:"labels,omitempty"`

	// (Number) Tokens for the request messages
	// Tokens for the request messages
	MessageTokens *float64 `json:"messageTokens,omitempty" tf:"message_tokens,omitempty"`

	// (Number) Priority
	// Priority
	Priority *float64 `json:"priority,omitempty" tf:"priority,omitempty"`

	// (String) Readable Request ID
	// Readable Request ID
	ReadableID *string `json:"readableId,omitempty" tf:"readable_id,omitempty"`

	// (String) Requested information from request
	// Requested information from request
	Request *string `json:"request,omitempty" tf:"request,omitempty"`

	// (String) Requirement
	// Requirement
	Requirement *string `json:"requirement,omitempty" tf:"requirement,omitempty"`

	// (String) Request Status
	// Request Status
	Status *string `json:"status,omitempty" tf:"status,omitempty"`

	// (String) Brief description of the request
	// Brief description of the request
	Summary *string `json:"summary,omitempty" tf:"summary,omitempty"`

	// (String) The CISA defined Traffic Light Protocol (TLP)
	// The CISA defined Traffic Light Protocol (TLP)
	Tlp *string `json:"tlp,omitempty" tf:"tlp,omitempty"`

	// (Number) Tokens for the request
	// Tokens for the request
	Tokens *float64 `json:"tokens,omitempty" tf:"tokens,omitempty"`

	// (String)
	Updated *string `json:"updated,omitempty" tf:"updated,omitempty"`
}

type OneRequestPriorityParameters struct {

	// (String) Identifier
	// Identifier
	// +kubebuilder:validation:Optional
	AccountIdentifier *string `json:"accountIdentifier,omitempty" tf:"account_identifier,omitempty"`

	// (List of String) List of labels
	// List of labels
	// +kubebuilder:validation:Optional
	Labels []*string `json:"labels,omitempty" tf:"labels,omitempty"`

	// (Number) Priority
	// Priority
	// +kubebuilder:validation:Optional
	Priority *float64 `json:"priority,omitempty" tf:"priority,omitempty"`

	// (String) Requirement
	// Requirement
	// +kubebuilder:validation:Optional
	Requirement *string `json:"requirement,omitempty" tf:"requirement,omitempty"`

	// (String) The CISA defined Traffic Light Protocol (TLP)
	// The CISA defined Traffic Light Protocol (TLP)
	// +kubebuilder:validation:Optional
	Tlp *string `json:"tlp,omitempty" tf:"tlp,omitempty"`
}

// OneRequestPrioritySpec defines the desired state of OneRequestPriority
type OneRequestPrioritySpec struct {
	v1.ResourceSpec `json:",inline"`
	ForProvider     OneRequestPriorityParameters `json:"forProvider"`
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
	InitProvider OneRequestPriorityInitParameters `json:"initProvider,omitempty"`
}

// OneRequestPriorityStatus defines the observed state of OneRequestPriority.
type OneRequestPriorityStatus struct {
	v1.ResourceStatus `json:",inline"`
	AtProvider        OneRequestPriorityObservation `json:"atProvider,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:storageversion

// OneRequestPriority is the Schema for the OneRequestPrioritys API.
// +kubebuilder:printcolumn:name="SYNCED",type="string",JSONPath=".status.conditions[?(@.type=='Synced')].status"
// +kubebuilder:printcolumn:name="READY",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="EXTERNAL-NAME",type="string",JSONPath=".metadata.annotations.crossplane\\.io/external-name"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:resource:scope=Cluster,categories={crossplane,managed,cloudflare}
type OneRequestPriority struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.accountIdentifier) || (has(self.initProvider) && has(self.initProvider.accountIdentifier))",message="spec.forProvider.accountIdentifier is a required parameter"
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.labels) || (has(self.initProvider) && has(self.initProvider.labels))",message="spec.forProvider.labels is a required parameter"
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.priority) || (has(self.initProvider) && has(self.initProvider.priority))",message="spec.forProvider.priority is a required parameter"
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.requirement) || (has(self.initProvider) && has(self.initProvider.requirement))",message="spec.forProvider.requirement is a required parameter"
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.tlp) || (has(self.initProvider) && has(self.initProvider.tlp))",message="spec.forProvider.tlp is a required parameter"
	Spec   OneRequestPrioritySpec   `json:"spec"`
	Status OneRequestPriorityStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// OneRequestPriorityList contains a list of OneRequestPrioritys
type OneRequestPriorityList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []OneRequestPriority `json:"items"`
}

// Repository type metadata.
var (
	OneRequestPriority_Kind             = "OneRequestPriority"
	OneRequestPriority_GroupKind        = schema.GroupKind{Group: CRDGroup, Kind: OneRequestPriority_Kind}.String()
	OneRequestPriority_KindAPIVersion   = OneRequestPriority_Kind + "." + CRDGroupVersion.String()
	OneRequestPriority_GroupVersionKind = CRDGroupVersion.WithKind(OneRequestPriority_Kind)
)

func init() {
	SchemeBuilder.Register(&OneRequestPriority{}, &OneRequestPriorityList{})
}
