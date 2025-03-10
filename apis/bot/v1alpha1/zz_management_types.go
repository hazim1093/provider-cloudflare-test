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

type ManagementInitParameters struct {

	// (String) Enable rule to block AI Scrapers and Crawlers.
	// Enable rule to block AI Scrapers and Crawlers.
	AIBotsProtection *string `json:"aiBotsProtection,omitempty" tf:"ai_bots_protection,omitempty"`

	// (Boolean) Automatically update to the newest bot detection models created by Cloudflare as they are released. Learn more.
	// Automatically update to the newest bot detection models created by Cloudflare as they are released. [Learn more.](https://developers.cloudflare.com/bots/reference/machine-learning-models#model-versions-and-release-notes)
	AutoUpdateModel *bool `json:"autoUpdateModel,omitempty" tf:"auto_update_model,omitempty"`

	// (Boolean) Use lightweight, invisible JavaScript detections to improve Bot Management. Learn more about JavaScript Detections.
	// Use lightweight, invisible JavaScript detections to improve Bot Management. [Learn more about JavaScript Detections](https://developers.cloudflare.com/bots/reference/javascript-detections/).
	EnableJs *bool `json:"enableJs,omitempty" tf:"enable_js,omitempty"`

	// (Boolean) Whether to enable Bot Fight Mode.
	// Whether to enable Bot Fight Mode.
	FightMode *bool `json:"fightMode,omitempty" tf:"fight_mode,omitempty"`

	// (Boolean) Whether to optimize Super Bot Fight Mode protections for Wordpress.
	// Whether to optimize Super Bot Fight Mode protections for Wordpress.
	OptimizeWordpress *bool `json:"optimizeWordpress,omitempty" tf:"optimize_wordpress,omitempty"`

	// (String) Super Bot Fight Mode (SBFM) action to take on definitely automated requests.
	// Super Bot Fight Mode (SBFM) action to take on definitely automated requests.
	SbfmDefinitelyAutomated *string `json:"sbfmDefinitelyAutomated,omitempty" tf:"sbfm_definitely_automated,omitempty"`

	// (String) Super Bot Fight Mode (SBFM) action to take on likely automated requests.
	// Super Bot Fight Mode (SBFM) action to take on likely automated requests.
	SbfmLikelyAutomated *string `json:"sbfmLikelyAutomated,omitempty" tf:"sbfm_likely_automated,omitempty"`

	// (Boolean) Super Bot Fight Mode (SBFM) to enable static resource protection.
	// Enable if static resources on your application need bot protection.
	// Note: Static resource protection can also result in legitimate traffic being blocked.
	// Super Bot Fight Mode (SBFM) to enable static resource protection.
	// Enable if static resources on your application need bot protection.
	// Note: Static resource protection can also result in legitimate traffic being blocked.
	SbfmStaticResourceProtection *bool `json:"sbfmStaticResourceProtection,omitempty" tf:"sbfm_static_resource_protection,omitempty"`

	// (String) Super Bot Fight Mode (SBFM) action to take on verified bots requests.
	// Super Bot Fight Mode (SBFM) action to take on verified bots requests.
	SbfmVerifiedBots *string `json:"sbfmVerifiedBots,omitempty" tf:"sbfm_verified_bots,omitempty"`

	// only field that shows which unauthorized settings are currently active on the zone. These settings typically result from upgrades or downgrades. (see below for nested schema)
	StaleZoneConfiguration *StaleZoneConfigurationInitParameters `json:"staleZoneConfiguration,omitempty" tf:"stale_zone_configuration,omitempty"`

	// (Boolean) Whether to disable tracking the highest bot score for a session in the Bot Management cookie.
	// Whether to disable tracking the highest bot score for a session in the Bot Management cookie.
	SuppressSessionScore *bool `json:"suppressSessionScore,omitempty" tf:"suppress_session_score,omitempty"`

	// (String) Identifier
	// Identifier
	ZoneID *string `json:"zoneId,omitempty" tf:"zone_id,omitempty"`
}

type ManagementObservation struct {

	// (String) Enable rule to block AI Scrapers and Crawlers.
	// Enable rule to block AI Scrapers and Crawlers.
	AIBotsProtection *string `json:"aiBotsProtection,omitempty" tf:"ai_bots_protection,omitempty"`

	// (Boolean) Automatically update to the newest bot detection models created by Cloudflare as they are released. Learn more.
	// Automatically update to the newest bot detection models created by Cloudflare as they are released. [Learn more.](https://developers.cloudflare.com/bots/reference/machine-learning-models#model-versions-and-release-notes)
	AutoUpdateModel *bool `json:"autoUpdateModel,omitempty" tf:"auto_update_model,omitempty"`

	// (Boolean) Use lightweight, invisible JavaScript detections to improve Bot Management. Learn more about JavaScript Detections.
	// Use lightweight, invisible JavaScript detections to improve Bot Management. [Learn more about JavaScript Detections](https://developers.cloudflare.com/bots/reference/javascript-detections/).
	EnableJs *bool `json:"enableJs,omitempty" tf:"enable_js,omitempty"`

	// (Boolean) Whether to enable Bot Fight Mode.
	// Whether to enable Bot Fight Mode.
	FightMode *bool `json:"fightMode,omitempty" tf:"fight_mode,omitempty"`

	// (String) Identifier
	ID *string `json:"id,omitempty" tf:"id,omitempty"`

	// (Boolean) Whether to optimize Super Bot Fight Mode protections for Wordpress.
	// Whether to optimize Super Bot Fight Mode protections for Wordpress.
	OptimizeWordpress *bool `json:"optimizeWordpress,omitempty" tf:"optimize_wordpress,omitempty"`

	// (String) Super Bot Fight Mode (SBFM) action to take on definitely automated requests.
	// Super Bot Fight Mode (SBFM) action to take on definitely automated requests.
	SbfmDefinitelyAutomated *string `json:"sbfmDefinitelyAutomated,omitempty" tf:"sbfm_definitely_automated,omitempty"`

	// (String) Super Bot Fight Mode (SBFM) action to take on likely automated requests.
	// Super Bot Fight Mode (SBFM) action to take on likely automated requests.
	SbfmLikelyAutomated *string `json:"sbfmLikelyAutomated,omitempty" tf:"sbfm_likely_automated,omitempty"`

	// (Boolean) Super Bot Fight Mode (SBFM) to enable static resource protection.
	// Enable if static resources on your application need bot protection.
	// Note: Static resource protection can also result in legitimate traffic being blocked.
	// Super Bot Fight Mode (SBFM) to enable static resource protection.
	// Enable if static resources on your application need bot protection.
	// Note: Static resource protection can also result in legitimate traffic being blocked.
	SbfmStaticResourceProtection *bool `json:"sbfmStaticResourceProtection,omitempty" tf:"sbfm_static_resource_protection,omitempty"`

	// (String) Super Bot Fight Mode (SBFM) action to take on verified bots requests.
	// Super Bot Fight Mode (SBFM) action to take on verified bots requests.
	SbfmVerifiedBots *string `json:"sbfmVerifiedBots,omitempty" tf:"sbfm_verified_bots,omitempty"`

	// only field that shows which unauthorized settings are currently active on the zone. These settings typically result from upgrades or downgrades. (see below for nested schema)
	StaleZoneConfiguration *StaleZoneConfigurationObservation `json:"staleZoneConfiguration,omitempty" tf:"stale_zone_configuration,omitempty"`

	// (Boolean) Whether to disable tracking the highest bot score for a session in the Bot Management cookie.
	// Whether to disable tracking the highest bot score for a session in the Bot Management cookie.
	SuppressSessionScore *bool `json:"suppressSessionScore,omitempty" tf:"suppress_session_score,omitempty"`

	// only field that indicates whether the zone currently is running the latest ML model.
	// A read-only field that indicates whether the zone currently is running the latest ML model.
	UsingLatestModel *bool `json:"usingLatestModel,omitempty" tf:"using_latest_model,omitempty"`

	// (String) Identifier
	// Identifier
	ZoneID *string `json:"zoneId,omitempty" tf:"zone_id,omitempty"`
}

type ManagementParameters struct {

	// (String) Enable rule to block AI Scrapers and Crawlers.
	// Enable rule to block AI Scrapers and Crawlers.
	// +kubebuilder:validation:Optional
	AIBotsProtection *string `json:"aiBotsProtection,omitempty" tf:"ai_bots_protection,omitempty"`

	// (Boolean) Automatically update to the newest bot detection models created by Cloudflare as they are released. Learn more.
	// Automatically update to the newest bot detection models created by Cloudflare as they are released. [Learn more.](https://developers.cloudflare.com/bots/reference/machine-learning-models#model-versions-and-release-notes)
	// +kubebuilder:validation:Optional
	AutoUpdateModel *bool `json:"autoUpdateModel,omitempty" tf:"auto_update_model,omitempty"`

	// (Boolean) Use lightweight, invisible JavaScript detections to improve Bot Management. Learn more about JavaScript Detections.
	// Use lightweight, invisible JavaScript detections to improve Bot Management. [Learn more about JavaScript Detections](https://developers.cloudflare.com/bots/reference/javascript-detections/).
	// +kubebuilder:validation:Optional
	EnableJs *bool `json:"enableJs,omitempty" tf:"enable_js,omitempty"`

	// (Boolean) Whether to enable Bot Fight Mode.
	// Whether to enable Bot Fight Mode.
	// +kubebuilder:validation:Optional
	FightMode *bool `json:"fightMode,omitempty" tf:"fight_mode,omitempty"`

	// (Boolean) Whether to optimize Super Bot Fight Mode protections for Wordpress.
	// Whether to optimize Super Bot Fight Mode protections for Wordpress.
	// +kubebuilder:validation:Optional
	OptimizeWordpress *bool `json:"optimizeWordpress,omitempty" tf:"optimize_wordpress,omitempty"`

	// (String) Super Bot Fight Mode (SBFM) action to take on definitely automated requests.
	// Super Bot Fight Mode (SBFM) action to take on definitely automated requests.
	// +kubebuilder:validation:Optional
	SbfmDefinitelyAutomated *string `json:"sbfmDefinitelyAutomated,omitempty" tf:"sbfm_definitely_automated,omitempty"`

	// (String) Super Bot Fight Mode (SBFM) action to take on likely automated requests.
	// Super Bot Fight Mode (SBFM) action to take on likely automated requests.
	// +kubebuilder:validation:Optional
	SbfmLikelyAutomated *string `json:"sbfmLikelyAutomated,omitempty" tf:"sbfm_likely_automated,omitempty"`

	// (Boolean) Super Bot Fight Mode (SBFM) to enable static resource protection.
	// Enable if static resources on your application need bot protection.
	// Note: Static resource protection can also result in legitimate traffic being blocked.
	// Super Bot Fight Mode (SBFM) to enable static resource protection.
	// Enable if static resources on your application need bot protection.
	// Note: Static resource protection can also result in legitimate traffic being blocked.
	// +kubebuilder:validation:Optional
	SbfmStaticResourceProtection *bool `json:"sbfmStaticResourceProtection,omitempty" tf:"sbfm_static_resource_protection,omitempty"`

	// (String) Super Bot Fight Mode (SBFM) action to take on verified bots requests.
	// Super Bot Fight Mode (SBFM) action to take on verified bots requests.
	// +kubebuilder:validation:Optional
	SbfmVerifiedBots *string `json:"sbfmVerifiedBots,omitempty" tf:"sbfm_verified_bots,omitempty"`

	// only field that shows which unauthorized settings are currently active on the zone. These settings typically result from upgrades or downgrades. (see below for nested schema)
	// +kubebuilder:validation:Optional
	StaleZoneConfiguration *StaleZoneConfigurationParameters `json:"staleZoneConfiguration,omitempty" tf:"stale_zone_configuration,omitempty"`

	// (Boolean) Whether to disable tracking the highest bot score for a session in the Bot Management cookie.
	// Whether to disable tracking the highest bot score for a session in the Bot Management cookie.
	// +kubebuilder:validation:Optional
	SuppressSessionScore *bool `json:"suppressSessionScore,omitempty" tf:"suppress_session_score,omitempty"`

	// (String) Identifier
	// Identifier
	// +kubebuilder:validation:Optional
	ZoneID *string `json:"zoneId,omitempty" tf:"zone_id,omitempty"`
}

type StaleZoneConfigurationInitParameters struct {
}

type StaleZoneConfigurationObservation struct {

	// (Boolean) Whether to enable Bot Fight Mode.
	// Indicates that the zone's Bot Fight Mode is turned on.
	FightMode *bool `json:"fightMode,omitempty" tf:"fight_mode,omitempty"`

	// (Boolean) Whether to optimize Super Bot Fight Mode protections for Wordpress.
	// Indicates that the zone's wordpress optimization for SBFM is turned on.
	OptimizeWordpress *bool `json:"optimizeWordpress,omitempty" tf:"optimize_wordpress,omitempty"`

	// (String) Super Bot Fight Mode (SBFM) action to take on definitely automated requests.
	// Indicates that the zone's definitely automated requests are being blocked or challenged.
	SbfmDefinitelyAutomated *string `json:"sbfmDefinitelyAutomated,omitempty" tf:"sbfm_definitely_automated,omitempty"`

	// (String) Super Bot Fight Mode (SBFM) action to take on likely automated requests.
	// Indicates that the zone's likely automated requests are being blocked or challenged.
	SbfmLikelyAutomated *string `json:"sbfmLikelyAutomated,omitempty" tf:"sbfm_likely_automated,omitempty"`

	// (Boolean) Super Bot Fight Mode (SBFM) to enable static resource protection.
	// Enable if static resources on your application need bot protection.
	// Note: Static resource protection can also result in legitimate traffic being blocked.
	// Indicates that the zone's static resource protection is turned on.
	SbfmStaticResourceProtection *string `json:"sbfmStaticResourceProtection,omitempty" tf:"sbfm_static_resource_protection,omitempty"`

	// (String) Super Bot Fight Mode (SBFM) action to take on verified bots requests.
	// Indicates that the zone's verified bot requests are being blocked.
	SbfmVerifiedBots *string `json:"sbfmVerifiedBots,omitempty" tf:"sbfm_verified_bots,omitempty"`

	// (Boolean) Whether to disable tracking the highest bot score for a session in the Bot Management cookie.
	// Indicates that the zone's session score tracking is disabled.
	SuppressSessionScore *bool `json:"suppressSessionScore,omitempty" tf:"suppress_session_score,omitempty"`
}

type StaleZoneConfigurationParameters struct {
}

// ManagementSpec defines the desired state of Management
type ManagementSpec struct {
	v1.ResourceSpec `json:",inline"`
	ForProvider     ManagementParameters `json:"forProvider"`
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
	InitProvider ManagementInitParameters `json:"initProvider,omitempty"`
}

// ManagementStatus defines the observed state of Management.
type ManagementStatus struct {
	v1.ResourceStatus `json:",inline"`
	AtProvider        ManagementObservation `json:"atProvider,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:storageversion

// Management is the Schema for the Managements API.
// +kubebuilder:printcolumn:name="SYNCED",type="string",JSONPath=".status.conditions[?(@.type=='Synced')].status"
// +kubebuilder:printcolumn:name="READY",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="EXTERNAL-NAME",type="string",JSONPath=".metadata.annotations.crossplane\\.io/external-name"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:resource:scope=Cluster,categories={crossplane,managed,cloudflare}
type Management struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.zoneId) || (has(self.initProvider) && has(self.initProvider.zoneId))",message="spec.forProvider.zoneId is a required parameter"
	Spec   ManagementSpec   `json:"spec"`
	Status ManagementStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// ManagementList contains a list of Managements
type ManagementList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Management `json:"items"`
}

// Repository type metadata.
var (
	Management_Kind             = "Management"
	Management_GroupKind        = schema.GroupKind{Group: CRDGroup, Kind: Management_Kind}.String()
	Management_KindAPIVersion   = Management_Kind + "." + CRDGroupVersion.String()
	Management_GroupVersionKind = CRDGroupVersion.WithKind(Management_Kind)
)

func init() {
	SchemeBuilder.Register(&Management{}, &ManagementList{})
}
