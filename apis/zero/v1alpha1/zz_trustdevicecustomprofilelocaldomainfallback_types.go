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

type DomainsInitParameters struct {

	// (List of String) A list of IP addresses to handle domain resolution.
	// A list of IP addresses to handle domain resolution.
	DNSServer []*string `json:"dnsServer,omitempty" tf:"dns_server,omitempty"`

	// (String) A description of the fallback domain, displayed in the client UI.
	// A description of the fallback domain, displayed in the client UI.
	Description *string `json:"description,omitempty" tf:"description,omitempty"`

	// (String) The domain suffix to match when resolving locally.
	// The domain suffix to match when resolving locally.
	Suffix *string `json:"suffix,omitempty" tf:"suffix,omitempty"`
}

type DomainsObservation struct {

	// (List of String) A list of IP addresses to handle domain resolution.
	// A list of IP addresses to handle domain resolution.
	DNSServer []*string `json:"dnsServer,omitempty" tf:"dns_server,omitempty"`

	// (String) A description of the fallback domain, displayed in the client UI.
	// A description of the fallback domain, displayed in the client UI.
	Description *string `json:"description,omitempty" tf:"description,omitempty"`

	// (String) The domain suffix to match when resolving locally.
	// The domain suffix to match when resolving locally.
	Suffix *string `json:"suffix,omitempty" tf:"suffix,omitempty"`
}

type DomainsParameters struct {

	// (List of String) A list of IP addresses to handle domain resolution.
	// A list of IP addresses to handle domain resolution.
	// +kubebuilder:validation:Optional
	DNSServer []*string `json:"dnsServer,omitempty" tf:"dns_server,omitempty"`

	// (String) A description of the fallback domain, displayed in the client UI.
	// A description of the fallback domain, displayed in the client UI.
	// +kubebuilder:validation:Optional
	Description *string `json:"description,omitempty" tf:"description,omitempty"`

	// (String) The domain suffix to match when resolving locally.
	// The domain suffix to match when resolving locally.
	// +kubebuilder:validation:Optional
	Suffix *string `json:"suffix" tf:"suffix,omitempty"`
}

type TrustDeviceCustomProfileLocalDomainFallbackInitParameters struct {

	// (String)
	AccountID *string `json:"accountId,omitempty" tf:"account_id,omitempty"`

	// (Attributes List) (see below for nested schema)
	Domains []DomainsInitParameters `json:"domains,omitempty" tf:"domains,omitempty"`

	// (String) Device ID.
	// Device ID.
	PolicyID *string `json:"policyId,omitempty" tf:"policy_id,omitempty"`
}

type TrustDeviceCustomProfileLocalDomainFallbackObservation struct {

	// (String)
	AccountID *string `json:"accountId,omitempty" tf:"account_id,omitempty"`

	// (List of String) A list of IP addresses to handle domain resolution.
	// A list of IP addresses to handle domain resolution.
	DNSServer []*string `json:"dnsServer,omitempty" tf:"dns_server,omitempty"`

	// (String) A description of the fallback domain, displayed in the client UI.
	// A description of the fallback domain, displayed in the client UI.
	Description *string `json:"description,omitempty" tf:"description,omitempty"`

	// (Attributes List) (see below for nested schema)
	Domains []DomainsObservation `json:"domains,omitempty" tf:"domains,omitempty"`

	// (String) Device ID.
	ID *string `json:"id,omitempty" tf:"id,omitempty"`

	// (String) Device ID.
	// Device ID.
	PolicyID *string `json:"policyId,omitempty" tf:"policy_id,omitempty"`

	// (String) The domain suffix to match when resolving locally.
	// The domain suffix to match when resolving locally.
	Suffix *string `json:"suffix,omitempty" tf:"suffix,omitempty"`
}

type TrustDeviceCustomProfileLocalDomainFallbackParameters struct {

	// (String)
	// +kubebuilder:validation:Optional
	AccountID *string `json:"accountId,omitempty" tf:"account_id,omitempty"`

	// (Attributes List) (see below for nested schema)
	// +kubebuilder:validation:Optional
	Domains []DomainsParameters `json:"domains,omitempty" tf:"domains,omitempty"`

	// (String) Device ID.
	// Device ID.
	// +kubebuilder:validation:Optional
	PolicyID *string `json:"policyId,omitempty" tf:"policy_id,omitempty"`
}

// TrustDeviceCustomProfileLocalDomainFallbackSpec defines the desired state of TrustDeviceCustomProfileLocalDomainFallback
type TrustDeviceCustomProfileLocalDomainFallbackSpec struct {
	v1.ResourceSpec `json:",inline"`
	ForProvider     TrustDeviceCustomProfileLocalDomainFallbackParameters `json:"forProvider"`
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
	InitProvider TrustDeviceCustomProfileLocalDomainFallbackInitParameters `json:"initProvider,omitempty"`
}

// TrustDeviceCustomProfileLocalDomainFallbackStatus defines the observed state of TrustDeviceCustomProfileLocalDomainFallback.
type TrustDeviceCustomProfileLocalDomainFallbackStatus struct {
	v1.ResourceStatus `json:",inline"`
	AtProvider        TrustDeviceCustomProfileLocalDomainFallbackObservation `json:"atProvider,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:storageversion

// TrustDeviceCustomProfileLocalDomainFallback is the Schema for the TrustDeviceCustomProfileLocalDomainFallbacks API.
// +kubebuilder:printcolumn:name="SYNCED",type="string",JSONPath=".status.conditions[?(@.type=='Synced')].status"
// +kubebuilder:printcolumn:name="READY",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="EXTERNAL-NAME",type="string",JSONPath=".metadata.annotations.crossplane\\.io/external-name"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:resource:scope=Cluster,categories={crossplane,managed,cloudflare}
type TrustDeviceCustomProfileLocalDomainFallback struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.accountId) || (has(self.initProvider) && has(self.initProvider.accountId))",message="spec.forProvider.accountId is a required parameter"
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.domains) || (has(self.initProvider) && has(self.initProvider.domains))",message="spec.forProvider.domains is a required parameter"
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.policyId) || (has(self.initProvider) && has(self.initProvider.policyId))",message="spec.forProvider.policyId is a required parameter"
	Spec   TrustDeviceCustomProfileLocalDomainFallbackSpec   `json:"spec"`
	Status TrustDeviceCustomProfileLocalDomainFallbackStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// TrustDeviceCustomProfileLocalDomainFallbackList contains a list of TrustDeviceCustomProfileLocalDomainFallbacks
type TrustDeviceCustomProfileLocalDomainFallbackList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []TrustDeviceCustomProfileLocalDomainFallback `json:"items"`
}

// Repository type metadata.
var (
	TrustDeviceCustomProfileLocalDomainFallback_Kind             = "TrustDeviceCustomProfileLocalDomainFallback"
	TrustDeviceCustomProfileLocalDomainFallback_GroupKind        = schema.GroupKind{Group: CRDGroup, Kind: TrustDeviceCustomProfileLocalDomainFallback_Kind}.String()
	TrustDeviceCustomProfileLocalDomainFallback_KindAPIVersion   = TrustDeviceCustomProfileLocalDomainFallback_Kind + "." + CRDGroupVersion.String()
	TrustDeviceCustomProfileLocalDomainFallback_GroupVersionKind = CRDGroupVersion.WithKind(TrustDeviceCustomProfileLocalDomainFallback_Kind)
)

func init() {
	SchemeBuilder.Register(&TrustDeviceCustomProfileLocalDomainFallback{}, &TrustDeviceCustomProfileLocalDomainFallbackList{})
}
