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

type ListInitParameters struct {

	// (String) Identifier
	// Identifier
	AccountID *string `json:"accountId,omitempty" tf:"account_id,omitempty"`

	// (String) An informative summary of the list.
	// An informative summary of the list.
	Description *string `json:"description,omitempty" tf:"description,omitempty"`

	// (String) The type of the list. Each type supports specific list items (IP addresses, ASNs, hostnames or redirects).
	// The type of the list. Each type supports specific list items (IP addresses, ASNs, hostnames or redirects).
	Kind *string `json:"kind,omitempty" tf:"kind,omitempty"`
}

type ListObservation struct {

	// (String) Identifier
	// Identifier
	AccountID *string `json:"accountId,omitempty" tf:"account_id,omitempty"`

	// (String) The RFC 3339 timestamp of when the list was created.
	// The RFC 3339 timestamp of when the list was created.
	CreatedOn *string `json:"createdOn,omitempty" tf:"created_on,omitempty"`

	// (String) An informative summary of the list.
	// An informative summary of the list.
	Description *string `json:"description,omitempty" tf:"description,omitempty"`

	// (String) The unique ID of the list.
	ID *string `json:"id,omitempty" tf:"id,omitempty"`

	// (String) The type of the list. Each type supports specific list items (IP addresses, ASNs, hostnames or redirects).
	// The type of the list. Each type supports specific list items (IP addresses, ASNs, hostnames or redirects).
	Kind *string `json:"kind,omitempty" tf:"kind,omitempty"`

	// (String) The RFC 3339 timestamp of when the list was last modified.
	// The RFC 3339 timestamp of when the list was last modified.
	ModifiedOn *string `json:"modifiedOn,omitempty" tf:"modified_on,omitempty"`

	// (Number) The number of items in the list.
	// The number of items in the list.
	NumItems *float64 `json:"numItems,omitempty" tf:"num_items,omitempty"`

	// (Number) The number of filters referencing the list.
	// The number of [filters](/operations/filters-list-filters) referencing the list.
	NumReferencingFilters *float64 `json:"numReferencingFilters,omitempty" tf:"num_referencing_filters,omitempty"`
}

type ListParameters struct {

	// (String) Identifier
	// Identifier
	// +kubebuilder:validation:Optional
	AccountID *string `json:"accountId,omitempty" tf:"account_id,omitempty"`

	// (String) An informative summary of the list.
	// An informative summary of the list.
	// +kubebuilder:validation:Optional
	Description *string `json:"description,omitempty" tf:"description,omitempty"`

	// (String) The type of the list. Each type supports specific list items (IP addresses, ASNs, hostnames or redirects).
	// The type of the list. Each type supports specific list items (IP addresses, ASNs, hostnames or redirects).
	// +kubebuilder:validation:Optional
	Kind *string `json:"kind,omitempty" tf:"kind,omitempty"`
}

// ListSpec defines the desired state of List
type ListSpec struct {
	v1.ResourceSpec `json:",inline"`
	ForProvider     ListParameters `json:"forProvider"`
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
	InitProvider ListInitParameters `json:"initProvider,omitempty"`
}

// ListStatus defines the observed state of List.
type ListStatus struct {
	v1.ResourceStatus `json:",inline"`
	AtProvider        ListObservation `json:"atProvider,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:storageversion

// List is the Schema for the Lists API.
// +kubebuilder:printcolumn:name="SYNCED",type="string",JSONPath=".status.conditions[?(@.type=='Synced')].status"
// +kubebuilder:printcolumn:name="READY",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="EXTERNAL-NAME",type="string",JSONPath=".metadata.annotations.crossplane\\.io/external-name"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:resource:scope=Cluster,categories={crossplane,managed,cloudflare-upjet}
type List struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.accountId) || (has(self.initProvider) && has(self.initProvider.accountId))",message="spec.forProvider.accountId is a required parameter"
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.kind) || (has(self.initProvider) && has(self.initProvider.kind))",message="spec.forProvider.kind is a required parameter"
	Spec   ListSpec   `json:"spec"`
	Status ListStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// ListList contains a list of Lists
type ListList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []List `json:"items"`
}

// Repository type metadata.
var (
	List_Kind             = "List"
	List_GroupKind        = schema.GroupKind{Group: CRDGroup, Kind: List_Kind}.String()
	List_KindAPIVersion   = List_Kind + "." + CRDGroupVersion.String()
	List_GroupVersionKind = CRDGroupVersion.WithKind(List_Kind)
)

func init() {
	SchemeBuilder.Register(&List{}, &ListList{})
}
