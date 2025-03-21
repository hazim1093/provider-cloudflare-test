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

type AnnotationsInitParameters struct {

	// readable message about the deployment. Truncated to 100 bytes.
	// Human-readable message about the deployment. Truncated to 100 bytes.
	WorkersMessage *string `json:"workersMessage,omitempty" tf:"workers_message,omitempty"`
}

type AnnotationsObservation struct {

	// readable message about the deployment. Truncated to 100 bytes.
	// Human-readable message about the deployment. Truncated to 100 bytes.
	WorkersMessage *string `json:"workersMessage,omitempty" tf:"workers_message,omitempty"`
}

type AnnotationsParameters struct {

	// readable message about the deployment. Truncated to 100 bytes.
	// Human-readable message about the deployment. Truncated to 100 bytes.
	// +kubebuilder:validation:Optional
	WorkersMessage *string `json:"workersMessage,omitempty" tf:"workers_message,omitempty"`
}

type DeploymentInitParameters struct {

	// (String) Identifier
	// Identifier
	AccountID *string `json:"accountId,omitempty" tf:"account_id,omitempty"`

	// (Attributes) (see below for nested schema)
	Annotations *AnnotationsInitParameters `json:"annotations,omitempty" tf:"annotations,omitempty"`

	// (Attributes List) (see below for nested schema)
	Deployments []DeploymentsInitParameters `json:"deployments,omitempty" tf:"deployments,omitempty"`

	// (String) Name of the script.
	// Name of the script.
	ScriptName *string `json:"scriptName,omitempty" tf:"script_name,omitempty"`

	// (String)
	Strategy *string `json:"strategy,omitempty" tf:"strategy,omitempty"`

	// (Attributes List) (see below for nested schema)
	Versions []DeploymentVersionsInitParameters `json:"versions,omitempty" tf:"versions,omitempty"`
}

type DeploymentObservation struct {

	// (String) Identifier
	// Identifier
	AccountID *string `json:"accountId,omitempty" tf:"account_id,omitempty"`

	// (Attributes) (see below for nested schema)
	Annotations *AnnotationsObservation `json:"annotations,omitempty" tf:"annotations,omitempty"`

	// (String)
	AuthorEmail *string `json:"authorEmail,omitempty" tf:"author_email,omitempty"`

	// (String)
	CreatedOn *string `json:"createdOn,omitempty" tf:"created_on,omitempty"`

	// (Attributes List) (see below for nested schema)
	Deployments []DeploymentsObservation `json:"deployments,omitempty" tf:"deployments,omitempty"`

	// (String) The ID of this resource.
	ID *string `json:"id,omitempty" tf:"id,omitempty"`

	// (String) Name of the script.
	// Name of the script.
	ScriptName *string `json:"scriptName,omitempty" tf:"script_name,omitempty"`

	// (String)
	Source *string `json:"source,omitempty" tf:"source,omitempty"`

	// (String)
	Strategy *string `json:"strategy,omitempty" tf:"strategy,omitempty"`

	// (Attributes List) (see below for nested schema)
	Versions []DeploymentVersionsObservation `json:"versions,omitempty" tf:"versions,omitempty"`
}

type DeploymentParameters struct {

	// (String) Identifier
	// Identifier
	// +kubebuilder:validation:Optional
	AccountID *string `json:"accountId,omitempty" tf:"account_id,omitempty"`

	// (Attributes) (see below for nested schema)
	// +kubebuilder:validation:Optional
	Annotations *AnnotationsParameters `json:"annotations,omitempty" tf:"annotations,omitempty"`

	// (Attributes List) (see below for nested schema)
	// +kubebuilder:validation:Optional
	Deployments []DeploymentsParameters `json:"deployments,omitempty" tf:"deployments,omitempty"`

	// (String) Name of the script.
	// Name of the script.
	// +kubebuilder:validation:Optional
	ScriptName *string `json:"scriptName,omitempty" tf:"script_name,omitempty"`

	// (String)
	// +kubebuilder:validation:Optional
	Strategy *string `json:"strategy,omitempty" tf:"strategy,omitempty"`

	// (Attributes List) (see below for nested schema)
	// +kubebuilder:validation:Optional
	Versions []DeploymentVersionsParameters `json:"versions,omitempty" tf:"versions,omitempty"`
}

type DeploymentVersionsInitParameters struct {

	// (Number)
	Percentage *float64 `json:"percentage,omitempty" tf:"percentage,omitempty"`

	// (String)
	VersionID *string `json:"versionId,omitempty" tf:"version_id,omitempty"`
}

type DeploymentVersionsObservation struct {

	// (Number)
	Percentage *float64 `json:"percentage,omitempty" tf:"percentage,omitempty"`

	// (String)
	VersionID *string `json:"versionId,omitempty" tf:"version_id,omitempty"`
}

type DeploymentVersionsParameters struct {

	// (Number)
	// +kubebuilder:validation:Optional
	Percentage *float64 `json:"percentage" tf:"percentage,omitempty"`

	// (String)
	// +kubebuilder:validation:Optional
	VersionID *string `json:"versionId" tf:"version_id,omitempty"`
}

type DeploymentsAnnotationsInitParameters struct {
}

type DeploymentsAnnotationsObservation struct {

	// readable message about the deployment. Truncated to 100 bytes.
	// Human-readable message about the deployment. Truncated to 100 bytes.
	WorkersMessage *string `json:"workersMessage,omitempty" tf:"workers_message,omitempty"`
}

type DeploymentsAnnotationsParameters struct {
}

type DeploymentsInitParameters struct {

	// (Attributes) (see below for nested schema)
	Annotations *DeploymentsAnnotationsInitParameters `json:"annotations,omitempty" tf:"annotations,omitempty"`

	// (Attributes List) (see below for nested schema)
	Versions []VersionsInitParameters `json:"versions,omitempty" tf:"versions,omitempty"`
}

type DeploymentsObservation struct {

	// (Attributes) (see below for nested schema)
	Annotations *DeploymentsAnnotationsObservation `json:"annotations,omitempty" tf:"annotations,omitempty"`

	// (String)
	AuthorEmail *string `json:"authorEmail,omitempty" tf:"author_email,omitempty"`

	// (String)
	CreatedOn *string `json:"createdOn,omitempty" tf:"created_on,omitempty"`

	// (String) The ID of this resource.
	ID *string `json:"id,omitempty" tf:"id,omitempty"`

	// (String)
	Source *string `json:"source,omitempty" tf:"source,omitempty"`

	// (String)
	Strategy *string `json:"strategy,omitempty" tf:"strategy,omitempty"`

	// (Attributes List) (see below for nested schema)
	Versions []VersionsObservation `json:"versions,omitempty" tf:"versions,omitempty"`
}

type DeploymentsParameters struct {

	// (Attributes) (see below for nested schema)
	// +kubebuilder:validation:Optional
	Annotations *DeploymentsAnnotationsParameters `json:"annotations,omitempty" tf:"annotations,omitempty"`

	// (Attributes List) (see below for nested schema)
	// +kubebuilder:validation:Optional
	Versions []VersionsParameters `json:"versions" tf:"versions,omitempty"`
}

type VersionsInitParameters struct {
}

type VersionsObservation struct {

	// (Number)
	Percentage *float64 `json:"percentage,omitempty" tf:"percentage,omitempty"`

	// (String)
	VersionID *string `json:"versionId,omitempty" tf:"version_id,omitempty"`
}

type VersionsParameters struct {
}

// DeploymentSpec defines the desired state of Deployment
type DeploymentSpec struct {
	v1.ResourceSpec `json:",inline"`
	ForProvider     DeploymentParameters `json:"forProvider"`
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
	InitProvider DeploymentInitParameters `json:"initProvider,omitempty"`
}

// DeploymentStatus defines the observed state of Deployment.
type DeploymentStatus struct {
	v1.ResourceStatus `json:",inline"`
	AtProvider        DeploymentObservation `json:"atProvider,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:storageversion

// Deployment is the Schema for the Deployments API.
// +kubebuilder:printcolumn:name="SYNCED",type="string",JSONPath=".status.conditions[?(@.type=='Synced')].status"
// +kubebuilder:printcolumn:name="READY",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="EXTERNAL-NAME",type="string",JSONPath=".metadata.annotations.crossplane\\.io/external-name"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:resource:scope=Cluster,categories={crossplane,managed,cloudflare}
type Deployment struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.accountId) || (has(self.initProvider) && has(self.initProvider.accountId))",message="spec.forProvider.accountId is a required parameter"
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.deployments) || (has(self.initProvider) && has(self.initProvider.deployments))",message="spec.forProvider.deployments is a required parameter"
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.scriptName) || (has(self.initProvider) && has(self.initProvider.scriptName))",message="spec.forProvider.scriptName is a required parameter"
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.strategy) || (has(self.initProvider) && has(self.initProvider.strategy))",message="spec.forProvider.strategy is a required parameter"
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.versions) || (has(self.initProvider) && has(self.initProvider.versions))",message="spec.forProvider.versions is a required parameter"
	Spec   DeploymentSpec   `json:"spec"`
	Status DeploymentStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// DeploymentList contains a list of Deployments
type DeploymentList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Deployment `json:"items"`
}

// Repository type metadata.
var (
	Deployment_Kind             = "Deployment"
	Deployment_GroupKind        = schema.GroupKind{Group: CRDGroup, Kind: Deployment_Kind}.String()
	Deployment_KindAPIVersion   = Deployment_Kind + "." + CRDGroupVersion.String()
	Deployment_GroupVersionKind = CRDGroupVersion.WithKind(Deployment_Kind)
)

func init() {
	SchemeBuilder.Register(&Deployment{}, &DeploymentList{})
}
