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

type SecretInitParameters struct {

	// (String) Identifier
	// Identifier
	AccountID *string `json:"accountId,omitempty" tf:"account_id,omitempty"`

	// (String) Name of the Workers for Platforms dispatch namespace.
	// Name of the Workers for Platforms dispatch namespace.
	DispatchNamespace *string `json:"dispatchNamespace,omitempty" tf:"dispatch_namespace,omitempty"`

	// (String) Name of the script, used in URLs and route configuration.
	// Name of the script, used in URLs and route configuration.
	ScriptName *string `json:"scriptName,omitempty" tf:"script_name,omitempty"`

	// (String) The value of the secret.
	// The value of the secret.
	Text *string `json:"text,omitempty" tf:"text,omitempty"`

	// (String) The type of secret to put.
	// The type of secret to put.
	Type *string `json:"type,omitempty" tf:"type,omitempty"`
}

type SecretObservation struct {

	// (String) Identifier
	// Identifier
	AccountID *string `json:"accountId,omitempty" tf:"account_id,omitempty"`

	// (String) Name of the Workers for Platforms dispatch namespace.
	// Name of the Workers for Platforms dispatch namespace.
	DispatchNamespace *string `json:"dispatchNamespace,omitempty" tf:"dispatch_namespace,omitempty"`

	// (String) The name of this secret, this is what will be used to access it inside the Worker.
	ID *string `json:"id,omitempty" tf:"id,omitempty"`

	// (String) Name of the script, used in URLs and route configuration.
	// Name of the script, used in URLs and route configuration.
	ScriptName *string `json:"scriptName,omitempty" tf:"script_name,omitempty"`

	// (String) The value of the secret.
	// The value of the secret.
	Text *string `json:"text,omitempty" tf:"text,omitempty"`

	// (String) The type of secret to put.
	// The type of secret to put.
	Type *string `json:"type,omitempty" tf:"type,omitempty"`
}

type SecretParameters struct {

	// (String) Identifier
	// Identifier
	// +kubebuilder:validation:Optional
	AccountID *string `json:"accountId,omitempty" tf:"account_id,omitempty"`

	// (String) Name of the Workers for Platforms dispatch namespace.
	// Name of the Workers for Platforms dispatch namespace.
	// +kubebuilder:validation:Optional
	DispatchNamespace *string `json:"dispatchNamespace,omitempty" tf:"dispatch_namespace,omitempty"`

	// (String) Name of the script, used in URLs and route configuration.
	// Name of the script, used in URLs and route configuration.
	// +kubebuilder:validation:Optional
	ScriptName *string `json:"scriptName,omitempty" tf:"script_name,omitempty"`

	// (String) The value of the secret.
	// The value of the secret.
	// +kubebuilder:validation:Optional
	Text *string `json:"text,omitempty" tf:"text,omitempty"`

	// (String) The type of secret to put.
	// The type of secret to put.
	// +kubebuilder:validation:Optional
	Type *string `json:"type,omitempty" tf:"type,omitempty"`
}

// SecretSpec defines the desired state of Secret
type SecretSpec struct {
	v1.ResourceSpec `json:",inline"`
	ForProvider     SecretParameters `json:"forProvider"`
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
	InitProvider SecretInitParameters `json:"initProvider,omitempty"`
}

// SecretStatus defines the observed state of Secret.
type SecretStatus struct {
	v1.ResourceStatus `json:",inline"`
	AtProvider        SecretObservation `json:"atProvider,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:storageversion

// Secret is the Schema for the Secrets API.
// +kubebuilder:printcolumn:name="SYNCED",type="string",JSONPath=".status.conditions[?(@.type=='Synced')].status"
// +kubebuilder:printcolumn:name="READY",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="EXTERNAL-NAME",type="string",JSONPath=".metadata.annotations.crossplane\\.io/external-name"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:resource:scope=Cluster,categories={crossplane,managed,cloudflare}
type Secret struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.accountId) || (has(self.initProvider) && has(self.initProvider.accountId))",message="spec.forProvider.accountId is a required parameter"
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.dispatchNamespace) || (has(self.initProvider) && has(self.initProvider.dispatchNamespace))",message="spec.forProvider.dispatchNamespace is a required parameter"
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.scriptName) || (has(self.initProvider) && has(self.initProvider.scriptName))",message="spec.forProvider.scriptName is a required parameter"
	Spec   SecretSpec   `json:"spec"`
	Status SecretStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// SecretList contains a list of Secrets
type SecretList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Secret `json:"items"`
}

// Repository type metadata.
var (
	Secret_Kind             = "Secret"
	Secret_GroupKind        = schema.GroupKind{Group: CRDGroup, Kind: Secret_Kind}.String()
	Secret_KindAPIVersion   = Secret_Kind + "." + CRDGroupVersion.String()
	Secret_GroupVersionKind = CRDGroupVersion.WithKind(Secret_Kind)
)

func init() {
	SchemeBuilder.Register(&Secret{}, &SecretList{})
}
