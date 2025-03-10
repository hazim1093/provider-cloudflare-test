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

type DeviceInitParameters struct {
}

type DeviceObservation struct {

	// (String) The ID of this resource.
	ID *string `json:"id,omitempty" tf:"id,omitempty"`

	// (String)
	SerialNumber *string `json:"serialNumber,omitempty" tf:"serial_number,omitempty"`
}

type DeviceParameters struct {
}

type TransitConnectorInitParameters struct {

	// (String) Account identifier
	// Account identifier
	AccountID *string `json:"accountId,omitempty" tf:"account_id,omitempty"`

	// (Boolean)
	Activated *bool `json:"activated,omitempty" tf:"activated,omitempty"`

	// (String)
	ConnectorID *string `json:"connectorId,omitempty" tf:"connector_id,omitempty"`

	// (Attributes) (see below for nested schema)
	Device *DeviceInitParameters `json:"device,omitempty" tf:"device,omitempty"`

	// (Number)
	InterruptWindowDurationHours *float64 `json:"interruptWindowDurationHours,omitempty" tf:"interrupt_window_duration_hours,omitempty"`

	// (Number)
	InterruptWindowHourOfDay *float64 `json:"interruptWindowHourOfDay,omitempty" tf:"interrupt_window_hour_of_day,omitempty"`

	// (String)
	Notes *string `json:"notes,omitempty" tf:"notes,omitempty"`

	// (String)
	Timezone *string `json:"timezone,omitempty" tf:"timezone,omitempty"`
}

type TransitConnectorObservation struct {

	// (String) Account identifier
	// Account identifier
	AccountID *string `json:"accountId,omitempty" tf:"account_id,omitempty"`

	// (Boolean)
	Activated *bool `json:"activated,omitempty" tf:"activated,omitempty"`

	// (String)
	ConnectorID *string `json:"connectorId,omitempty" tf:"connector_id,omitempty"`

	// (Attributes) (see below for nested schema)
	Device *DeviceObservation `json:"device,omitempty" tf:"device,omitempty"`

	// (String) The ID of this resource.
	ID *string `json:"id,omitempty" tf:"id,omitempty"`

	// (Number)
	InterruptWindowDurationHours *float64 `json:"interruptWindowDurationHours,omitempty" tf:"interrupt_window_duration_hours,omitempty"`

	// (Number)
	InterruptWindowHourOfDay *float64 `json:"interruptWindowHourOfDay,omitempty" tf:"interrupt_window_hour_of_day,omitempty"`

	// (String)
	LastHeartbeat *string `json:"lastHeartbeat,omitempty" tf:"last_heartbeat,omitempty"`

	// (String)
	LastSeenVersion *string `json:"lastSeenVersion,omitempty" tf:"last_seen_version,omitempty"`

	// (String)
	LastUpdated *string `json:"lastUpdated,omitempty" tf:"last_updated,omitempty"`

	// (String)
	Notes *string `json:"notes,omitempty" tf:"notes,omitempty"`

	// (String)
	Timezone *string `json:"timezone,omitempty" tf:"timezone,omitempty"`
}

type TransitConnectorParameters struct {

	// (String) Account identifier
	// Account identifier
	// +kubebuilder:validation:Optional
	AccountID *string `json:"accountId,omitempty" tf:"account_id,omitempty"`

	// (Boolean)
	// +kubebuilder:validation:Optional
	Activated *bool `json:"activated,omitempty" tf:"activated,omitempty"`

	// (String)
	// +kubebuilder:validation:Optional
	ConnectorID *string `json:"connectorId,omitempty" tf:"connector_id,omitempty"`

	// (Attributes) (see below for nested schema)
	// +kubebuilder:validation:Optional
	Device *DeviceParameters `json:"device,omitempty" tf:"device,omitempty"`

	// (Number)
	// +kubebuilder:validation:Optional
	InterruptWindowDurationHours *float64 `json:"interruptWindowDurationHours,omitempty" tf:"interrupt_window_duration_hours,omitempty"`

	// (Number)
	// +kubebuilder:validation:Optional
	InterruptWindowHourOfDay *float64 `json:"interruptWindowHourOfDay,omitempty" tf:"interrupt_window_hour_of_day,omitempty"`

	// (String)
	// +kubebuilder:validation:Optional
	Notes *string `json:"notes,omitempty" tf:"notes,omitempty"`

	// (String)
	// +kubebuilder:validation:Optional
	Timezone *string `json:"timezone,omitempty" tf:"timezone,omitempty"`
}

// TransitConnectorSpec defines the desired state of TransitConnector
type TransitConnectorSpec struct {
	v1.ResourceSpec `json:",inline"`
	ForProvider     TransitConnectorParameters `json:"forProvider"`
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
	InitProvider TransitConnectorInitParameters `json:"initProvider,omitempty"`
}

// TransitConnectorStatus defines the observed state of TransitConnector.
type TransitConnectorStatus struct {
	v1.ResourceStatus `json:",inline"`
	AtProvider        TransitConnectorObservation `json:"atProvider,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:storageversion

// TransitConnector is the Schema for the TransitConnectors API.
// +kubebuilder:printcolumn:name="SYNCED",type="string",JSONPath=".status.conditions[?(@.type=='Synced')].status"
// +kubebuilder:printcolumn:name="READY",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="EXTERNAL-NAME",type="string",JSONPath=".metadata.annotations.crossplane\\.io/external-name"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:resource:scope=Cluster,categories={crossplane,managed,cloudflare}
type TransitConnector struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.accountId) || (has(self.initProvider) && has(self.initProvider.accountId))",message="spec.forProvider.accountId is a required parameter"
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.connectorId) || (has(self.initProvider) && has(self.initProvider.connectorId))",message="spec.forProvider.connectorId is a required parameter"
	Spec   TransitConnectorSpec   `json:"spec"`
	Status TransitConnectorStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// TransitConnectorList contains a list of TransitConnectors
type TransitConnectorList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []TransitConnector `json:"items"`
}

// Repository type metadata.
var (
	TransitConnector_Kind             = "TransitConnector"
	TransitConnector_GroupKind        = schema.GroupKind{Group: CRDGroup, Kind: TransitConnector_Kind}.String()
	TransitConnector_KindAPIVersion   = TransitConnector_Kind + "." + CRDGroupVersion.String()
	TransitConnector_GroupVersionKind = CRDGroupVersion.WithKind(TransitConnector_Kind)
)

func init() {
	SchemeBuilder.Register(&TransitConnector{}, &TransitConnectorList{})
}
