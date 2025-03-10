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

type CronTriggerInitParameters struct {

	// (String) Identifier
	// Identifier
	AccountID *string `json:"accountId,omitempty" tf:"account_id,omitempty"`

	// (Attributes List) (see below for nested schema)
	Schedules []SchedulesInitParameters `json:"schedules,omitempty" tf:"schedules,omitempty"`

	// (String) Name of the script, used in URLs and route configuration.
	// Name of the script, used in URLs and route configuration.
	ScriptName *string `json:"scriptName,omitempty" tf:"script_name,omitempty"`
}

type CronTriggerObservation struct {

	// (String) Identifier
	// Identifier
	AccountID *string `json:"accountId,omitempty" tf:"account_id,omitempty"`

	// (String) Name of the script, used in URLs and route configuration.
	ID *string `json:"id,omitempty" tf:"id,omitempty"`

	// (Attributes List) (see below for nested schema)
	Schedules []SchedulesObservation `json:"schedules,omitempty" tf:"schedules,omitempty"`

	// (String) Name of the script, used in URLs and route configuration.
	// Name of the script, used in URLs and route configuration.
	ScriptName *string `json:"scriptName,omitempty" tf:"script_name,omitempty"`
}

type CronTriggerParameters struct {

	// (String) Identifier
	// Identifier
	// +kubebuilder:validation:Optional
	AccountID *string `json:"accountId,omitempty" tf:"account_id,omitempty"`

	// (Attributes List) (see below for nested schema)
	// +kubebuilder:validation:Optional
	Schedules []SchedulesParameters `json:"schedules,omitempty" tf:"schedules,omitempty"`

	// (String) Name of the script, used in URLs and route configuration.
	// Name of the script, used in URLs and route configuration.
	// +kubebuilder:validation:Optional
	ScriptName *string `json:"scriptName,omitempty" tf:"script_name,omitempty"`
}

type SchedulesInitParameters struct {

	// (String)
	Cron *string `json:"cron,omitempty" tf:"cron,omitempty"`
}

type SchedulesObservation struct {

	// (String)
	Cron *string `json:"cron,omitempty" tf:"cron,omitempty"`
}

type SchedulesParameters struct {

	// (String)
	// +kubebuilder:validation:Optional
	Cron *string `json:"cron" tf:"cron,omitempty"`
}

// CronTriggerSpec defines the desired state of CronTrigger
type CronTriggerSpec struct {
	v1.ResourceSpec `json:",inline"`
	ForProvider     CronTriggerParameters `json:"forProvider"`
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
	InitProvider CronTriggerInitParameters `json:"initProvider,omitempty"`
}

// CronTriggerStatus defines the observed state of CronTrigger.
type CronTriggerStatus struct {
	v1.ResourceStatus `json:",inline"`
	AtProvider        CronTriggerObservation `json:"atProvider,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:storageversion

// CronTrigger is the Schema for the CronTriggers API.
// +kubebuilder:printcolumn:name="SYNCED",type="string",JSONPath=".status.conditions[?(@.type=='Synced')].status"
// +kubebuilder:printcolumn:name="READY",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="EXTERNAL-NAME",type="string",JSONPath=".metadata.annotations.crossplane\\.io/external-name"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:resource:scope=Cluster,categories={crossplane,managed,cloudflare-upjet}
type CronTrigger struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.accountId) || (has(self.initProvider) && has(self.initProvider.accountId))",message="spec.forProvider.accountId is a required parameter"
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.schedules) || (has(self.initProvider) && has(self.initProvider.schedules))",message="spec.forProvider.schedules is a required parameter"
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.scriptName) || (has(self.initProvider) && has(self.initProvider.scriptName))",message="spec.forProvider.scriptName is a required parameter"
	Spec   CronTriggerSpec   `json:"spec"`
	Status CronTriggerStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// CronTriggerList contains a list of CronTriggers
type CronTriggerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []CronTrigger `json:"items"`
}

// Repository type metadata.
var (
	CronTrigger_Kind             = "CronTrigger"
	CronTrigger_GroupKind        = schema.GroupKind{Group: CRDGroup, Kind: CronTrigger_Kind}.String()
	CronTrigger_KindAPIVersion   = CronTrigger_Kind + "." + CRDGroupVersion.String()
	CronTrigger_GroupVersionKind = CRDGroupVersion.WithKind(CronTrigger_Kind)
)

func init() {
	SchemeBuilder.Register(&CronTrigger{}, &CronTriggerList{})
}
