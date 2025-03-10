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

type ErrorsInitParameters struct {
}

type ErrorsObservation struct {

	// (Number)
	Code *float64 `json:"code,omitempty" tf:"code,omitempty"`

	// (String)
	Message *string `json:"message,omitempty" tf:"message,omitempty"`
}

type ErrorsParameters struct {
}

type MessagesInitParameters struct {
}

type MessagesObservation struct {

	// (Number)
	Code *float64 `json:"code,omitempty" tf:"code,omitempty"`

	// (String)
	Message *string `json:"message,omitempty" tf:"message,omitempty"`
}

type MessagesParameters struct {
}

type MissingInitParameters struct {
}

type MissingObservation struct {

	// (String) DNS record content.
	// DNS record content.
	Content *string `json:"content,omitempty" tf:"content,omitempty"`

	// (String) Domain of your zone.
	// DNS record name (or @ for the zone apex).
	Name *string `json:"name,omitempty" tf:"name,omitempty"`

	// (Number) Required for MX, SRV and URI records. Unused by other record types. Records with lower priorities are preferred.
	// Required for MX, SRV and URI records. Unused by other record types. Records with lower priorities are preferred.
	Priority *float64 `json:"priority,omitempty" tf:"priority,omitempty"`

	// (Number) Time to live, in seconds, of the DNS record. Must be between 60 and 86400, or 1 for 'automatic'.
	// Time to live, in seconds, of the DNS record. Must be between 60 and 86400, or 1 for 'automatic'.
	TTL *float64 `json:"ttl,omitempty" tf:"ttl,omitempty"`

	// (String) DNS record type.
	// DNS record type.
	Type *string `json:"type,omitempty" tf:"type,omitempty"`
}

type MissingParameters struct {
}

type RecordInitParameters struct {
}

type RecordObservation struct {

	// (String) DNS record content.
	// DNS record content.
	Content *string `json:"content,omitempty" tf:"content,omitempty"`

	// (String) Domain of your zone.
	// DNS record name (or @ for the zone apex).
	Name *string `json:"name,omitempty" tf:"name,omitempty"`

	// (Number) Required for MX, SRV and URI records. Unused by other record types. Records with lower priorities are preferred.
	// Required for MX, SRV and URI records. Unused by other record types. Records with lower priorities are preferred.
	Priority *float64 `json:"priority,omitempty" tf:"priority,omitempty"`

	// (Number) Time to live, in seconds, of the DNS record. Must be between 60 and 86400, or 1 for 'automatic'.
	// Time to live, in seconds, of the DNS record. Must be between 60 and 86400, or 1 for 'automatic'.
	TTL *float64 `json:"ttl,omitempty" tf:"ttl,omitempty"`

	// (String) DNS record type.
	// DNS record type.
	Type *string `json:"type,omitempty" tf:"type,omitempty"`
}

type RecordParameters struct {
}

type ResultErrorsInitParameters struct {

	// (Attributes) List of records needed to enable an Email Routing zone. (see below for nested schema)
	Missing *MissingInitParameters `json:"missing,omitempty" tf:"missing,omitempty"`
}

type ResultErrorsObservation struct {

	// (Number)
	Code *string `json:"code,omitempty" tf:"code,omitempty"`

	// (Attributes) List of records needed to enable an Email Routing zone. (see below for nested schema)
	Missing *MissingObservation `json:"missing,omitempty" tf:"missing,omitempty"`
}

type ResultErrorsParameters struct {

	// (Attributes) List of records needed to enable an Email Routing zone. (see below for nested schema)
	// +kubebuilder:validation:Optional
	Missing *MissingParameters `json:"missing,omitempty" tf:"missing,omitempty"`
}

type ResultInfoInitParameters struct {
}

type ResultInfoObservation struct {

	// (Number) Total number of results for the requested service
	// Total number of results for the requested service
	Count *float64 `json:"count,omitempty" tf:"count,omitempty"`

	// (Number) Current page within paginated list of results
	// Current page within paginated list of results
	Page *float64 `json:"page,omitempty" tf:"page,omitempty"`

	// (Number) Number of results per page of results
	// Number of results per page of results
	PerPage *float64 `json:"perPage,omitempty" tf:"per_page,omitempty"`

	// (Number) Total results available without any search parameters
	// Total results available without any search parameters
	TotalCount *float64 `json:"totalCount,omitempty" tf:"total_count,omitempty"`
}

type ResultInfoParameters struct {
}

type ResultInitParameters struct {

	// (Attributes List) (see below for nested schema)
	Errors []ResultErrorsInitParameters `json:"errors,omitempty" tf:"errors,omitempty"`

	// (Attributes List) (see below for nested schema)
	Record []RecordInitParameters `json:"record,omitempty" tf:"record,omitempty"`
}

type ResultObservation struct {

	// (String) DNS record content.
	// DNS record content.
	Content *string `json:"content,omitempty" tf:"content,omitempty"`

	// (Attributes List) (see below for nested schema)
	Errors []ResultErrorsObservation `json:"errors,omitempty" tf:"errors,omitempty"`

	// (String) Domain of your zone.
	// DNS record name (or @ for the zone apex).
	Name *string `json:"name,omitempty" tf:"name,omitempty"`

	// (Number) Required for MX, SRV and URI records. Unused by other record types. Records with lower priorities are preferred.
	// Required for MX, SRV and URI records. Unused by other record types. Records with lower priorities are preferred.
	Priority *float64 `json:"priority,omitempty" tf:"priority,omitempty"`

	// (Attributes List) (see below for nested schema)
	Record []RecordObservation `json:"record,omitempty" tf:"record,omitempty"`

	// (Number) Time to live, in seconds, of the DNS record. Must be between 60 and 86400, or 1 for 'automatic'.
	// Time to live, in seconds, of the DNS record. Must be between 60 and 86400, or 1 for 'automatic'.
	TTL *float64 `json:"ttl,omitempty" tf:"ttl,omitempty"`

	// (String) DNS record type.
	// DNS record type.
	Type *string `json:"type,omitempty" tf:"type,omitempty"`
}

type ResultParameters struct {

	// (Attributes List) (see below for nested schema)
	// +kubebuilder:validation:Optional
	Errors []ResultErrorsParameters `json:"errors" tf:"errors,omitempty"`

	// (Attributes List) (see below for nested schema)
	// +kubebuilder:validation:Optional
	Record []RecordParameters `json:"record" tf:"record,omitempty"`
}

type RoutingDNSInitParameters struct {

	// (Attributes List) (see below for nested schema)
	Errors []ErrorsInitParameters `json:"errors,omitempty" tf:"errors,omitempty"`

	// (Attributes List) (see below for nested schema)
	Messages []MessagesInitParameters `json:"messages,omitempty" tf:"messages,omitempty"`

	// (Attributes) (see below for nested schema)
	Result *ResultInitParameters `json:"result,omitempty" tf:"result,omitempty"`

	// (Attributes) (see below for nested schema)
	ResultInfo *ResultInfoInitParameters `json:"resultInfo,omitempty" tf:"result_info,omitempty"`

	// (String) Identifier
	// Identifier
	ZoneID *string `json:"zoneId,omitempty" tf:"zone_id,omitempty"`
}

type RoutingDNSObservation struct {

	// (String) The date and time the settings have been created.
	// The date and time the settings have been created.
	Created *string `json:"created,omitempty" tf:"created,omitempty"`

	// (Boolean) State of the zone settings for Email Routing.
	// State of the zone settings for Email Routing.
	Enabled *bool `json:"enabled,omitempty" tf:"enabled,omitempty"`

	// (Attributes List) (see below for nested schema)
	Errors []ErrorsObservation `json:"errors,omitempty" tf:"errors,omitempty"`

	// (String) Identifier
	ID *string `json:"id,omitempty" tf:"id,omitempty"`

	// (Attributes List) (see below for nested schema)
	Messages []MessagesObservation `json:"messages,omitempty" tf:"messages,omitempty"`

	// (String) The date and time the settings have been modified.
	// The date and time the settings have been modified.
	Modified *string `json:"modified,omitempty" tf:"modified,omitempty"`

	// (Attributes) (see below for nested schema)
	Result *ResultObservation `json:"result,omitempty" tf:"result,omitempty"`

	// (Attributes) (see below for nested schema)
	ResultInfo *ResultInfoObservation `json:"resultInfo,omitempty" tf:"result_info,omitempty"`

	// (Boolean) Flag to check if the user skipped the configuration wizard.
	// Flag to check if the user skipped the configuration wizard.
	SkipWizard *bool `json:"skipWizard,omitempty" tf:"skip_wizard,omitempty"`

	// (String) Show the state of your account, and the type or configuration error.
	// Show the state of your account, and the type or configuration error.
	Status *string `json:"status,omitempty" tf:"status,omitempty"`

	// (Boolean) Whether the API call was successful
	// Whether the API call was successful
	Success *bool `json:"success,omitempty" tf:"success,omitempty"`

	// (String) Email Routing settings tag. (Deprecated, replaced by Email Routing settings identifier)
	// Email Routing settings tag. (Deprecated, replaced by Email Routing settings identifier)
	Tag *string `json:"tag,omitempty" tf:"tag,omitempty"`

	// (String) Identifier
	// Identifier
	ZoneID *string `json:"zoneId,omitempty" tf:"zone_id,omitempty"`
}

type RoutingDNSParameters struct {

	// (Attributes List) (see below for nested schema)
	// +kubebuilder:validation:Optional
	Errors []ErrorsParameters `json:"errors,omitempty" tf:"errors,omitempty"`

	// (Attributes List) (see below for nested schema)
	// +kubebuilder:validation:Optional
	Messages []MessagesParameters `json:"messages,omitempty" tf:"messages,omitempty"`

	// (Attributes) (see below for nested schema)
	// +kubebuilder:validation:Optional
	Result *ResultParameters `json:"result,omitempty" tf:"result,omitempty"`

	// (Attributes) (see below for nested schema)
	// +kubebuilder:validation:Optional
	ResultInfo *ResultInfoParameters `json:"resultInfo,omitempty" tf:"result_info,omitempty"`

	// (String) Identifier
	// Identifier
	// +kubebuilder:validation:Optional
	ZoneID *string `json:"zoneId,omitempty" tf:"zone_id,omitempty"`
}

// RoutingDNSSpec defines the desired state of RoutingDNS
type RoutingDNSSpec struct {
	v1.ResourceSpec `json:",inline"`
	ForProvider     RoutingDNSParameters `json:"forProvider"`
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
	InitProvider RoutingDNSInitParameters `json:"initProvider,omitempty"`
}

// RoutingDNSStatus defines the observed state of RoutingDNS.
type RoutingDNSStatus struct {
	v1.ResourceStatus `json:",inline"`
	AtProvider        RoutingDNSObservation `json:"atProvider,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:storageversion

// RoutingDNS is the Schema for the RoutingDNSs API.
// +kubebuilder:printcolumn:name="SYNCED",type="string",JSONPath=".status.conditions[?(@.type=='Synced')].status"
// +kubebuilder:printcolumn:name="READY",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="EXTERNAL-NAME",type="string",JSONPath=".metadata.annotations.crossplane\\.io/external-name"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:resource:scope=Cluster,categories={crossplane,managed,cloudflare}
type RoutingDNS struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.errors) || (has(self.initProvider) && has(self.initProvider.errors))",message="spec.forProvider.errors is a required parameter"
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.messages) || (has(self.initProvider) && has(self.initProvider.messages))",message="spec.forProvider.messages is a required parameter"
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.zoneId) || (has(self.initProvider) && has(self.initProvider.zoneId))",message="spec.forProvider.zoneId is a required parameter"
	Spec   RoutingDNSSpec   `json:"spec"`
	Status RoutingDNSStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// RoutingDNSList contains a list of RoutingDNSs
type RoutingDNSList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []RoutingDNS `json:"items"`
}

// Repository type metadata.
var (
	RoutingDNS_Kind             = "RoutingDNS"
	RoutingDNS_GroupKind        = schema.GroupKind{Group: CRDGroup, Kind: RoutingDNS_Kind}.String()
	RoutingDNS_KindAPIVersion   = RoutingDNS_Kind + "." + CRDGroupVersion.String()
	RoutingDNS_GroupVersionKind = CRDGroupVersion.WithKind(RoutingDNS_Kind)
)

func init() {
	SchemeBuilder.Register(&RoutingDNS{}, &RoutingDNSList{})
}
