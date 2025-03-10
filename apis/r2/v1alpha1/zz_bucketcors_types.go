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

type AllowedInitParameters struct {

	// Control-Allow-Headers header R2 sets when requesting objects in this bucket from a browser. Cross-origin requests that include custom headers (e.g. x-user-id) should specify these headers as AllowedHeaders.
	// Specifies the value for the Access-Control-Allow-Headers header R2 sets when requesting objects in this bucket from a browser. Cross-origin requests that include custom headers (e.g. x-user-id) should specify these headers as AllowedHeaders.
	Headers []*string `json:"headers,omitempty" tf:"headers,omitempty"`

	// Control-Allow-Methods header R2 sets when requesting objects in a bucket from a browser.
	// Specifies the value for the Access-Control-Allow-Methods header R2 sets when requesting objects in a bucket from a browser.
	Methods []*string `json:"methods,omitempty" tf:"methods,omitempty"`

	// Control-Allow-Origin header R2 sets when requesting objects in a bucket from a browser.
	// Specifies the value for the Access-Control-Allow-Origin header R2 sets when requesting objects in a bucket from a browser.
	Origins []*string `json:"origins,omitempty" tf:"origins,omitempty"`
}

type AllowedObservation struct {

	// Control-Allow-Headers header R2 sets when requesting objects in this bucket from a browser. Cross-origin requests that include custom headers (e.g. x-user-id) should specify these headers as AllowedHeaders.
	// Specifies the value for the Access-Control-Allow-Headers header R2 sets when requesting objects in this bucket from a browser. Cross-origin requests that include custom headers (e.g. x-user-id) should specify these headers as AllowedHeaders.
	Headers []*string `json:"headers,omitempty" tf:"headers,omitempty"`

	// Control-Allow-Methods header R2 sets when requesting objects in a bucket from a browser.
	// Specifies the value for the Access-Control-Allow-Methods header R2 sets when requesting objects in a bucket from a browser.
	Methods []*string `json:"methods,omitempty" tf:"methods,omitempty"`

	// Control-Allow-Origin header R2 sets when requesting objects in a bucket from a browser.
	// Specifies the value for the Access-Control-Allow-Origin header R2 sets when requesting objects in a bucket from a browser.
	Origins []*string `json:"origins,omitempty" tf:"origins,omitempty"`
}

type AllowedParameters struct {

	// Control-Allow-Headers header R2 sets when requesting objects in this bucket from a browser. Cross-origin requests that include custom headers (e.g. x-user-id) should specify these headers as AllowedHeaders.
	// Specifies the value for the Access-Control-Allow-Headers header R2 sets when requesting objects in this bucket from a browser. Cross-origin requests that include custom headers (e.g. x-user-id) should specify these headers as AllowedHeaders.
	// +kubebuilder:validation:Optional
	Headers []*string `json:"headers,omitempty" tf:"headers,omitempty"`

	// Control-Allow-Methods header R2 sets when requesting objects in a bucket from a browser.
	// Specifies the value for the Access-Control-Allow-Methods header R2 sets when requesting objects in a bucket from a browser.
	// +kubebuilder:validation:Optional
	Methods []*string `json:"methods" tf:"methods,omitempty"`

	// Control-Allow-Origin header R2 sets when requesting objects in a bucket from a browser.
	// Specifies the value for the Access-Control-Allow-Origin header R2 sets when requesting objects in a bucket from a browser.
	// +kubebuilder:validation:Optional
	Origins []*string `json:"origins" tf:"origins,omitempty"`
}

type BucketCorsInitParameters struct {

	// (String) Account ID
	// Account ID
	AccountID *string `json:"accountId,omitempty" tf:"account_id,omitempty"`

	// (String) Name of the bucket
	// Name of the bucket
	BucketName *string `json:"bucketName,omitempty" tf:"bucket_name,omitempty"`

	// (Attributes List) (see below for nested schema)
	Rules []RulesInitParameters `json:"rules,omitempty" tf:"rules,omitempty"`
}

type BucketCorsObservation struct {

	// (String) Account ID
	// Account ID
	AccountID *string `json:"accountId,omitempty" tf:"account_id,omitempty"`

	// (String) Name of the bucket
	// Name of the bucket
	BucketName *string `json:"bucketName,omitempty" tf:"bucket_name,omitempty"`

	// (String) Identifier for this rule
	ID *string `json:"id,omitempty" tf:"id,omitempty"`

	// (Attributes List) (see below for nested schema)
	Rules []RulesObservation `json:"rules,omitempty" tf:"rules,omitempty"`
}

type BucketCorsParameters struct {

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
	Rules []RulesParameters `json:"rules,omitempty" tf:"rules,omitempty"`
}

type RulesInitParameters struct {

	// (Attributes) Object specifying allowed origins, methods and headers for this CORS rule. (see below for nested schema)
	Allowed *AllowedInitParameters `json:"allowed,omitempty" tf:"allowed,omitempty"`

	// origin request. If you need to access headers beyond the safelisted response headers, such as Content-Encoding or cf-cache-status, you must specify it here.
	// Specifies the headers that can be exposed back, and accessed by, the JavaScript making the cross-origin request. If you need to access headers beyond the safelisted response headers, such as Content-Encoding or cf-cache-status, you must specify it here.
	ExposeHeaders []*string `json:"exposeHeaders,omitempty" tf:"expose_headers,omitempty"`

	// (String) Identifier for this rule
	// Identifier for this rule
	ID *string `json:"id,omitempty" tf:"id,omitempty"`

	// (Number) Specifies the amount of time (in seconds) browsers are allowed to cache CORS preflight responses. Browsers may limit this to 2 hours or less, even if the maximum value (86400) is specified.
	// Specifies the amount of time (in seconds) browsers are allowed to cache CORS preflight responses. Browsers may limit this to 2 hours or less, even if the maximum value (86400) is specified.
	MaxAgeSeconds *float64 `json:"maxAgeSeconds,omitempty" tf:"max_age_seconds,omitempty"`
}

type RulesObservation struct {

	// (Attributes) Object specifying allowed origins, methods and headers for this CORS rule. (see below for nested schema)
	Allowed *AllowedObservation `json:"allowed,omitempty" tf:"allowed,omitempty"`

	// origin request. If you need to access headers beyond the safelisted response headers, such as Content-Encoding or cf-cache-status, you must specify it here.
	// Specifies the headers that can be exposed back, and accessed by, the JavaScript making the cross-origin request. If you need to access headers beyond the safelisted response headers, such as Content-Encoding or cf-cache-status, you must specify it here.
	ExposeHeaders []*string `json:"exposeHeaders,omitempty" tf:"expose_headers,omitempty"`

	// (String) Identifier for this rule
	// Identifier for this rule
	ID *string `json:"id,omitempty" tf:"id,omitempty"`

	// (Number) Specifies the amount of time (in seconds) browsers are allowed to cache CORS preflight responses. Browsers may limit this to 2 hours or less, even if the maximum value (86400) is specified.
	// Specifies the amount of time (in seconds) browsers are allowed to cache CORS preflight responses. Browsers may limit this to 2 hours or less, even if the maximum value (86400) is specified.
	MaxAgeSeconds *float64 `json:"maxAgeSeconds,omitempty" tf:"max_age_seconds,omitempty"`
}

type RulesParameters struct {

	// (Attributes) Object specifying allowed origins, methods and headers for this CORS rule. (see below for nested schema)
	// +kubebuilder:validation:Optional
	Allowed *AllowedParameters `json:"allowed" tf:"allowed,omitempty"`

	// origin request. If you need to access headers beyond the safelisted response headers, such as Content-Encoding or cf-cache-status, you must specify it here.
	// Specifies the headers that can be exposed back, and accessed by, the JavaScript making the cross-origin request. If you need to access headers beyond the safelisted response headers, such as Content-Encoding or cf-cache-status, you must specify it here.
	// +kubebuilder:validation:Optional
	ExposeHeaders []*string `json:"exposeHeaders,omitempty" tf:"expose_headers,omitempty"`

	// (String) Identifier for this rule
	// Identifier for this rule
	// +kubebuilder:validation:Optional
	ID *string `json:"id,omitempty" tf:"id,omitempty"`

	// (Number) Specifies the amount of time (in seconds) browsers are allowed to cache CORS preflight responses. Browsers may limit this to 2 hours or less, even if the maximum value (86400) is specified.
	// Specifies the amount of time (in seconds) browsers are allowed to cache CORS preflight responses. Browsers may limit this to 2 hours or less, even if the maximum value (86400) is specified.
	// +kubebuilder:validation:Optional
	MaxAgeSeconds *float64 `json:"maxAgeSeconds,omitempty" tf:"max_age_seconds,omitempty"`
}

// BucketCorsSpec defines the desired state of BucketCors
type BucketCorsSpec struct {
	v1.ResourceSpec `json:",inline"`
	ForProvider     BucketCorsParameters `json:"forProvider"`
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
	InitProvider BucketCorsInitParameters `json:"initProvider,omitempty"`
}

// BucketCorsStatus defines the observed state of BucketCors.
type BucketCorsStatus struct {
	v1.ResourceStatus `json:",inline"`
	AtProvider        BucketCorsObservation `json:"atProvider,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:storageversion

// BucketCors is the Schema for the BucketCorss API.
// +kubebuilder:printcolumn:name="SYNCED",type="string",JSONPath=".status.conditions[?(@.type=='Synced')].status"
// +kubebuilder:printcolumn:name="READY",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="EXTERNAL-NAME",type="string",JSONPath=".metadata.annotations.crossplane\\.io/external-name"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:resource:scope=Cluster,categories={crossplane,managed,cloudflare}
type BucketCors struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.accountId) || (has(self.initProvider) && has(self.initProvider.accountId))",message="spec.forProvider.accountId is a required parameter"
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.bucketName) || (has(self.initProvider) && has(self.initProvider.bucketName))",message="spec.forProvider.bucketName is a required parameter"
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.rules) || (has(self.initProvider) && has(self.initProvider.rules))",message="spec.forProvider.rules is a required parameter"
	Spec   BucketCorsSpec   `json:"spec"`
	Status BucketCorsStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// BucketCorsList contains a list of BucketCorss
type BucketCorsList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []BucketCors `json:"items"`
}

// Repository type metadata.
var (
	BucketCors_Kind             = "BucketCors"
	BucketCors_GroupKind        = schema.GroupKind{Group: CRDGroup, Kind: BucketCors_Kind}.String()
	BucketCors_KindAPIVersion   = BucketCors_Kind + "." + CRDGroupVersion.String()
	BucketCors_GroupVersionKind = CRDGroupVersion.WithKind(BucketCors_Kind)
)

func init() {
	SchemeBuilder.Register(&BucketCors{}, &BucketCorsList{})
}
