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

type BucketLockInitParameters struct {

	// (String) Account ID
	// Account ID
	AccountID *string `json:"accountId,omitempty" tf:"account_id,omitempty"`

	// (String) Name of the bucket
	// Name of the bucket
	BucketName *string `json:"bucketName,omitempty" tf:"bucket_name,omitempty"`

	// (Attributes List) (see below for nested schema)
	Rules []BucketLockRulesInitParameters `json:"rules,omitempty" tf:"rules,omitempty"`
}

type BucketLockObservation struct {

	// (String) Account ID
	// Account ID
	AccountID *string `json:"accountId,omitempty" tf:"account_id,omitempty"`

	// (String) Name of the bucket
	// Name of the bucket
	BucketName *string `json:"bucketName,omitempty" tf:"bucket_name,omitempty"`

	// (String) Unique identifier for this rule
	ID *string `json:"id,omitempty" tf:"id,omitempty"`

	// (Attributes List) (see below for nested schema)
	Rules []BucketLockRulesObservation `json:"rules,omitempty" tf:"rules,omitempty"`
}

type BucketLockParameters struct {

	// (String) Account ID
	// Account ID
	// +kubebuilder:validation:Optional
	AccountID *string `json:"accountId,omitempty" tf:"account_id,omitempty"`

	// (String) Name of the bucket
	// Name of the bucket
	// +kubebuilder:validation:Optional
	BucketName *string `json:"bucketName,omitempty" tf:"bucket_name,omitempty"`

	// (Attributes List) (see below for nested schema)
	// +kubebuilder:validation:Optional
	Rules []BucketLockRulesParameters `json:"rules,omitempty" tf:"rules,omitempty"`
}

type BucketLockRulesInitParameters struct {

	// (Attributes) Condition to apply a lock rule to an object for how long in seconds (see below for nested schema)
	Condition *RulesConditionInitParameters `json:"condition,omitempty" tf:"condition,omitempty"`

	// (Boolean) Whether or not this rule is in effect
	// Whether or not this rule is in effect
	Enabled *bool `json:"enabled,omitempty" tf:"enabled,omitempty"`

	// (String) Unique identifier for this rule
	// Unique identifier for this rule
	ID *string `json:"id,omitempty" tf:"id,omitempty"`

	// (String) Rule will only apply to objects/uploads in the bucket that start with the given prefix, an empty prefix can be provided to scope rule to all objects/uploads
	// Rule will only apply to objects/uploads in the bucket that start with the given prefix, an empty prefix can be provided to scope rule to all objects/uploads
	Prefix *string `json:"prefix,omitempty" tf:"prefix,omitempty"`
}

type BucketLockRulesObservation struct {

	// (Attributes) Condition to apply a lock rule to an object for how long in seconds (see below for nested schema)
	Condition *RulesConditionObservation `json:"condition,omitempty" tf:"condition,omitempty"`

	// (Boolean) Whether or not this rule is in effect
	// Whether or not this rule is in effect
	Enabled *bool `json:"enabled,omitempty" tf:"enabled,omitempty"`

	// (String) Unique identifier for this rule
	// Unique identifier for this rule
	ID *string `json:"id,omitempty" tf:"id,omitempty"`

	// (String) Rule will only apply to objects/uploads in the bucket that start with the given prefix, an empty prefix can be provided to scope rule to all objects/uploads
	// Rule will only apply to objects/uploads in the bucket that start with the given prefix, an empty prefix can be provided to scope rule to all objects/uploads
	Prefix *string `json:"prefix,omitempty" tf:"prefix,omitempty"`
}

type BucketLockRulesParameters struct {

	// (Attributes) Condition to apply a lock rule to an object for how long in seconds (see below for nested schema)
	// +kubebuilder:validation:Optional
	Condition *RulesConditionParameters `json:"condition" tf:"condition,omitempty"`

	// (Boolean) Whether or not this rule is in effect
	// Whether or not this rule is in effect
	// +kubebuilder:validation:Optional
	Enabled *bool `json:"enabled" tf:"enabled,omitempty"`

	// (String) Unique identifier for this rule
	// Unique identifier for this rule
	// +kubebuilder:validation:Optional
	ID *string `json:"id" tf:"id,omitempty"`

	// (String) Rule will only apply to objects/uploads in the bucket that start with the given prefix, an empty prefix can be provided to scope rule to all objects/uploads
	// Rule will only apply to objects/uploads in the bucket that start with the given prefix, an empty prefix can be provided to scope rule to all objects/uploads
	// +kubebuilder:validation:Optional
	Prefix *string `json:"prefix,omitempty" tf:"prefix,omitempty"`
}

type RulesConditionInitParameters struct {

	// (String)
	Date *string `json:"date,omitempty" tf:"date,omitempty"`

	// (Number)
	MaxAgeSeconds *float64 `json:"maxAgeSeconds,omitempty" tf:"max_age_seconds,omitempty"`

	// (String)
	Type *string `json:"type,omitempty" tf:"type,omitempty"`
}

type RulesConditionObservation struct {

	// (String)
	Date *string `json:"date,omitempty" tf:"date,omitempty"`

	// (Number)
	MaxAgeSeconds *float64 `json:"maxAgeSeconds,omitempty" tf:"max_age_seconds,omitempty"`

	// (String)
	Type *string `json:"type,omitempty" tf:"type,omitempty"`
}

type RulesConditionParameters struct {

	// (String)
	// +kubebuilder:validation:Optional
	Date *string `json:"date,omitempty" tf:"date,omitempty"`

	// (Number)
	// +kubebuilder:validation:Optional
	MaxAgeSeconds *float64 `json:"maxAgeSeconds,omitempty" tf:"max_age_seconds,omitempty"`

	// (String)
	// +kubebuilder:validation:Optional
	Type *string `json:"type" tf:"type,omitempty"`
}

// BucketLockSpec defines the desired state of BucketLock
type BucketLockSpec struct {
	v1.ResourceSpec `json:",inline"`
	ForProvider     BucketLockParameters `json:"forProvider"`
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
	InitProvider BucketLockInitParameters `json:"initProvider,omitempty"`
}

// BucketLockStatus defines the observed state of BucketLock.
type BucketLockStatus struct {
	v1.ResourceStatus `json:",inline"`
	AtProvider        BucketLockObservation `json:"atProvider,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:storageversion

// BucketLock is the Schema for the BucketLocks API.
// +kubebuilder:printcolumn:name="SYNCED",type="string",JSONPath=".status.conditions[?(@.type=='Synced')].status"
// +kubebuilder:printcolumn:name="READY",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="EXTERNAL-NAME",type="string",JSONPath=".metadata.annotations.crossplane\\.io/external-name"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:resource:scope=Cluster,categories={crossplane,managed,cloudflare}
type BucketLock struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.accountId) || (has(self.initProvider) && has(self.initProvider.accountId))",message="spec.forProvider.accountId is a required parameter"
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.bucketName) || (has(self.initProvider) && has(self.initProvider.bucketName))",message="spec.forProvider.bucketName is a required parameter"
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.rules) || (has(self.initProvider) && has(self.initProvider.rules))",message="spec.forProvider.rules is a required parameter"
	Spec   BucketLockSpec   `json:"spec"`
	Status BucketLockStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// BucketLockList contains a list of BucketLocks
type BucketLockList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []BucketLock `json:"items"`
}

// Repository type metadata.
var (
	BucketLock_Kind             = "BucketLock"
	BucketLock_GroupKind        = schema.GroupKind{Group: CRDGroup, Kind: BucketLock_Kind}.String()
	BucketLock_KindAPIVersion   = BucketLock_Kind + "." + CRDGroupVersion.String()
	BucketLock_GroupVersionKind = CRDGroupVersion.WithKind(BucketLock_Kind)
)

func init() {
	SchemeBuilder.Register(&BucketLock{}, &BucketLockList{})
}
