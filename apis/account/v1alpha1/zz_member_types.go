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

type MemberInitParameters struct {

	// (String) Account identifier tag.
	// Account identifier tag.
	AccountID *string `json:"accountId,omitempty" tf:"account_id,omitempty"`

	// (String) The contact email address of the user.
	// The contact email address of the user.
	Email *string `json:"email,omitempty" tf:"email,omitempty"`

	// (Attributes List) Array of policies associated with this member. (see below for nested schema)
	Policies []PoliciesInitParameters `json:"policies,omitempty" tf:"policies,omitempty"`

	// (List of String) Array of roles associated with this member.
	// Array of roles associated with this member.
	Roles []*string `json:"roles,omitempty" tf:"roles,omitempty"`

	// (String)
	Status *string `json:"status,omitempty" tf:"status,omitempty"`

	// (Attributes) Details of the user associated to the membership. (see below for nested schema)
	User *UserInitParameters `json:"user,omitempty" tf:"user,omitempty"`
}

type MemberObservation struct {

	// (String) Account identifier tag.
	// Account identifier tag.
	AccountID *string `json:"accountId,omitempty" tf:"account_id,omitempty"`

	// (String) The contact email address of the user.
	// The contact email address of the user.
	Email *string `json:"email,omitempty" tf:"email,omitempty"`

	// (String) Membership identifier tag.
	ID *string `json:"id,omitempty" tf:"id,omitempty"`

	// (Attributes List) Array of policies associated with this member. (see below for nested schema)
	Policies []PoliciesObservation `json:"policies,omitempty" tf:"policies,omitempty"`

	// (List of String) Array of roles associated with this member.
	// Array of roles associated with this member.
	Roles []*string `json:"roles,omitempty" tf:"roles,omitempty"`

	// (String)
	Status *string `json:"status,omitempty" tf:"status,omitempty"`

	// (Attributes) Details of the user associated to the membership. (see below for nested schema)
	User *UserObservation `json:"user,omitempty" tf:"user,omitempty"`
}

type MemberParameters struct {

	// (String) Account identifier tag.
	// Account identifier tag.
	// +kubebuilder:validation:Optional
	AccountID *string `json:"accountId,omitempty" tf:"account_id,omitempty"`

	// (String) The contact email address of the user.
	// The contact email address of the user.
	// +kubebuilder:validation:Optional
	Email *string `json:"email,omitempty" tf:"email,omitempty"`

	// (Attributes List) Array of policies associated with this member. (see below for nested schema)
	// +kubebuilder:validation:Optional
	Policies []PoliciesParameters `json:"policies,omitempty" tf:"policies,omitempty"`

	// (List of String) Array of roles associated with this member.
	// Array of roles associated with this member.
	// +kubebuilder:validation:Optional
	Roles []*string `json:"roles,omitempty" tf:"roles,omitempty"`

	// (String)
	// +kubebuilder:validation:Optional
	Status *string `json:"status,omitempty" tf:"status,omitempty"`

	// (Attributes) Details of the user associated to the membership. (see below for nested schema)
	// +kubebuilder:validation:Optional
	User *UserParameters `json:"user,omitempty" tf:"user,omitempty"`
}

type PermissionGroupsInitParameters struct {

	// (String) Membership identifier tag.
	// Identifier of the group.
	ID *string `json:"id,omitempty" tf:"id,omitempty"`
}

type PermissionGroupsObservation struct {

	// (String) Membership identifier tag.
	// Identifier of the group.
	ID *string `json:"id,omitempty" tf:"id,omitempty"`
}

type PermissionGroupsParameters struct {

	// (String) Membership identifier tag.
	// Identifier of the group.
	// +kubebuilder:validation:Optional
	ID *string `json:"id" tf:"id,omitempty"`
}

type PoliciesInitParameters struct {

	// (String) Allow or deny operations against the resources.
	// Allow or deny operations against the resources.
	Access *string `json:"access,omitempty" tf:"access,omitempty"`

	// (Attributes List) A set of permission groups that are specified to the policy. (see below for nested schema)
	PermissionGroups []PermissionGroupsInitParameters `json:"permissionGroups,omitempty" tf:"permission_groups,omitempty"`

	// (Attributes List) A list of resource groups that the policy applies to. (see below for nested schema)
	ResourceGroups []ResourceGroupsInitParameters `json:"resourceGroups,omitempty" tf:"resource_groups,omitempty"`
}

type PoliciesObservation struct {

	// (String) Allow or deny operations against the resources.
	// Allow or deny operations against the resources.
	Access *string `json:"access,omitempty" tf:"access,omitempty"`

	// (String) Membership identifier tag.
	// Policy identifier.
	ID *string `json:"id,omitempty" tf:"id,omitempty"`

	// (Attributes List) A set of permission groups that are specified to the policy. (see below for nested schema)
	PermissionGroups []PermissionGroupsObservation `json:"permissionGroups,omitempty" tf:"permission_groups,omitempty"`

	// (Attributes List) A list of resource groups that the policy applies to. (see below for nested schema)
	ResourceGroups []ResourceGroupsObservation `json:"resourceGroups,omitempty" tf:"resource_groups,omitempty"`
}

type PoliciesParameters struct {

	// (String) Allow or deny operations against the resources.
	// Allow or deny operations against the resources.
	// +kubebuilder:validation:Optional
	Access *string `json:"access" tf:"access,omitempty"`

	// (Attributes List) A set of permission groups that are specified to the policy. (see below for nested schema)
	// +kubebuilder:validation:Optional
	PermissionGroups []PermissionGroupsParameters `json:"permissionGroups" tf:"permission_groups,omitempty"`

	// (Attributes List) A list of resource groups that the policy applies to. (see below for nested schema)
	// +kubebuilder:validation:Optional
	ResourceGroups []ResourceGroupsParameters `json:"resourceGroups" tf:"resource_groups,omitempty"`
}

type ResourceGroupsInitParameters struct {

	// (String) Membership identifier tag.
	// Identifier of the group.
	ID *string `json:"id,omitempty" tf:"id,omitempty"`
}

type ResourceGroupsObservation struct {

	// (String) Membership identifier tag.
	// Identifier of the group.
	ID *string `json:"id,omitempty" tf:"id,omitempty"`
}

type ResourceGroupsParameters struct {

	// (String) Membership identifier tag.
	// Identifier of the group.
	// +kubebuilder:validation:Optional
	ID *string `json:"id" tf:"id,omitempty"`
}

type UserInitParameters struct {
}

type UserObservation struct {

	// (String) The contact email address of the user.
	// The contact email address of the user.
	Email *string `json:"email,omitempty" tf:"email,omitempty"`

	// (String) User's first name
	// User's first name
	FirstName *string `json:"firstName,omitempty" tf:"first_name,omitempty"`

	// (String) Membership identifier tag.
	// Identifier
	ID *string `json:"id,omitempty" tf:"id,omitempty"`

	// (String) User's last name
	// User's last name
	LastName *string `json:"lastName,omitempty" tf:"last_name,omitempty"`

	// factor authentication is enabled for the user account. Does not apply to API authentication.
	// Indicates whether two-factor authentication is enabled for the user account. Does not apply to API authentication.
	TwoFactorAuthenticationEnabled *bool `json:"twoFactorAuthenticationEnabled,omitempty" tf:"two_factor_authentication_enabled,omitempty"`
}

type UserParameters struct {
}

// MemberSpec defines the desired state of Member
type MemberSpec struct {
	v1.ResourceSpec `json:",inline"`
	ForProvider     MemberParameters `json:"forProvider"`
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
	InitProvider MemberInitParameters `json:"initProvider,omitempty"`
}

// MemberStatus defines the observed state of Member.
type MemberStatus struct {
	v1.ResourceStatus `json:",inline"`
	AtProvider        MemberObservation `json:"atProvider,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:storageversion

// Member is the Schema for the Members API.
// +kubebuilder:printcolumn:name="SYNCED",type="string",JSONPath=".status.conditions[?(@.type=='Synced')].status"
// +kubebuilder:printcolumn:name="READY",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="EXTERNAL-NAME",type="string",JSONPath=".metadata.annotations.crossplane\\.io/external-name"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:resource:scope=Cluster,categories={crossplane,managed,cloudflare}
type Member struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.accountId) || (has(self.initProvider) && has(self.initProvider.accountId))",message="spec.forProvider.accountId is a required parameter"
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.email) || (has(self.initProvider) && has(self.initProvider.email))",message="spec.forProvider.email is a required parameter"
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.policies) || (has(self.initProvider) && has(self.initProvider.policies))",message="spec.forProvider.policies is a required parameter"
	Spec   MemberSpec   `json:"spec"`
	Status MemberStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// MemberList contains a list of Members
type MemberList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Member `json:"items"`
}

// Repository type metadata.
var (
	Member_Kind             = "Member"
	Member_GroupKind        = schema.GroupKind{Group: CRDGroup, Kind: Member_Kind}.String()
	Member_KindAPIVersion   = Member_Kind + "." + CRDGroupVersion.String()
	Member_GroupVersionKind = CRDGroupVersion.WithKind(Member_Kind)
)

func init() {
	SchemeBuilder.Register(&Member{}, &MemberList{})
}
