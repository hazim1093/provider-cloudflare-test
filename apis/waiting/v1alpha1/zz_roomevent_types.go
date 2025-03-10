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

type RoomEventInitParameters struct {

	// (String) If set, the event will override the waiting room's custom_page_html property while it is active. If null, the event will inherit it.
	// If set, the event will override the waiting room's `custom_page_html` property while it is active. If null, the event will inherit it.
	CustomPageHTML *string `json:"customPageHtml,omitempty" tf:"custom_page_html,omitempty"`

	// (String) A note that you can use to add more details about the event.
	// A note that you can use to add more details about the event.
	Description *string `json:"description,omitempty" tf:"description,omitempty"`

	// (Boolean) If set, the event will override the waiting room's disable_session_renewal property while it is active. If null, the event will inherit it.
	// If set, the event will override the waiting room's `disable_session_renewal` property while it is active. If null, the event will inherit it.
	DisableSessionRenewal *bool `json:"disableSessionRenewal,omitempty" tf:"disable_session_renewal,omitempty"`

	// (String) An ISO 8601 timestamp that marks the end of the event.
	// An ISO 8601 timestamp that marks the end of the event.
	EventEndTime *string `json:"eventEndTime,omitempty" tf:"event_end_time,omitempty"`

	// (String) An ISO 8601 timestamp that marks the start of the event. At this time, queued users will be processed with the event's configuration. The start time must be at least one minute before event_end_time.
	// An ISO 8601 timestamp that marks the start of the event. At this time, queued users will be processed with the event's configuration. The start time must be at least one minute before `event_end_time`.
	EventStartTime *string `json:"eventStartTime,omitempty" tf:"event_start_time,omitempty"`

	// (Number) If set, the event will override the waiting room's new_users_per_minute property while it is active. If null, the event will inherit it. This can only be set if the event's total_active_users property is also set.
	// If set, the event will override the waiting room's `new_users_per_minute` property while it is active. If null, the event will inherit it. This can only be set if the event's `total_active_users` property is also set.
	NewUsersPerMinute *float64 `json:"newUsersPerMinute,omitempty" tf:"new_users_per_minute,omitempty"`

	// (String) An ISO 8601 timestamp that marks when to begin queueing all users before the event starts. The prequeue must start at least five minutes before event_start_time.
	// An ISO 8601 timestamp that marks when to begin queueing all users before the event starts. The prequeue must start at least five minutes before `event_start_time`.
	PrequeueStartTime *string `json:"prequeueStartTime,omitempty" tf:"prequeue_start_time,omitempty"`

	// (String) If set, the event will override the waiting room's queueing_method property while it is active. If null, the event will inherit it.
	// If set, the event will override the waiting room's `queueing_method` property while it is active. If null, the event will inherit it.
	QueueingMethod *string `json:"queueingMethod,omitempty" tf:"queueing_method,omitempty"`

	// (Number) If set, the event will override the waiting room's session_duration property while it is active. If null, the event will inherit it.
	// If set, the event will override the waiting room's `session_duration` property while it is active. If null, the event will inherit it.
	SessionDuration *float64 `json:"sessionDuration,omitempty" tf:"session_duration,omitempty"`

	// (Boolean) If enabled, users in the prequeue will be shuffled randomly at the event_start_time. Requires that prequeue_start_time is not null. This is useful for situations when many users will join the event prequeue at the same time and you want to shuffle them to ensure fairness. Naturally, it makes the most sense to enable this feature when the queueing_method during the event respects ordering such as fifo, or else the shuffling may be unnecessary.
	// If enabled, users in the prequeue will be shuffled randomly at the `event_start_time`. Requires that `prequeue_start_time` is not null. This is useful for situations when many users will join the event prequeue at the same time and you want to shuffle them to ensure fairness. Naturally, it makes the most sense to enable this feature when the `queueing_method` during the event respects ordering such as **fifo**, or else the shuffling may be unnecessary.
	ShuffleAtEventStart *bool `json:"shuffleAtEventStart,omitempty" tf:"shuffle_at_event_start,omitempty"`

	// (Boolean) Suspends or allows an event. If set to true, the event is ignored and traffic will be handled based on the waiting room configuration.
	// Suspends or allows an event. If set to `true`, the event is ignored and traffic will be handled based on the waiting room configuration.
	Suspended *bool `json:"suspended,omitempty" tf:"suspended,omitempty"`

	// (Number) If set, the event will override the waiting room's total_active_users property while it is active. If null, the event will inherit it. This can only be set if the event's new_users_per_minute property is also set.
	// If set, the event will override the waiting room's `total_active_users` property while it is active. If null, the event will inherit it. This can only be set if the event's `new_users_per_minute` property is also set.
	TotalActiveUsers *float64 `json:"totalActiveUsers,omitempty" tf:"total_active_users,omitempty"`

	// (String)
	WaitingRoomID *string `json:"waitingRoomId,omitempty" tf:"waiting_room_id,omitempty"`

	// (String) Identifier
	// Identifier
	ZoneID *string `json:"zoneId,omitempty" tf:"zone_id,omitempty"`
}

type RoomEventObservation struct {

	// (String)
	CreatedOn *string `json:"createdOn,omitempty" tf:"created_on,omitempty"`

	// (String) If set, the event will override the waiting room's custom_page_html property while it is active. If null, the event will inherit it.
	// If set, the event will override the waiting room's `custom_page_html` property while it is active. If null, the event will inherit it.
	CustomPageHTML *string `json:"customPageHtml,omitempty" tf:"custom_page_html,omitempty"`

	// (String) A note that you can use to add more details about the event.
	// A note that you can use to add more details about the event.
	Description *string `json:"description,omitempty" tf:"description,omitempty"`

	// (Boolean) If set, the event will override the waiting room's disable_session_renewal property while it is active. If null, the event will inherit it.
	// If set, the event will override the waiting room's `disable_session_renewal` property while it is active. If null, the event will inherit it.
	DisableSessionRenewal *bool `json:"disableSessionRenewal,omitempty" tf:"disable_session_renewal,omitempty"`

	// (String) An ISO 8601 timestamp that marks the end of the event.
	// An ISO 8601 timestamp that marks the end of the event.
	EventEndTime *string `json:"eventEndTime,omitempty" tf:"event_end_time,omitempty"`

	// (String) An ISO 8601 timestamp that marks the start of the event. At this time, queued users will be processed with the event's configuration. The start time must be at least one minute before event_end_time.
	// An ISO 8601 timestamp that marks the start of the event. At this time, queued users will be processed with the event's configuration. The start time must be at least one minute before `event_end_time`.
	EventStartTime *string `json:"eventStartTime,omitempty" tf:"event_start_time,omitempty"`

	// (String) The ID of this resource.
	ID *string `json:"id,omitempty" tf:"id,omitempty"`

	// (String)
	ModifiedOn *string `json:"modifiedOn,omitempty" tf:"modified_on,omitempty"`

	// (Number) If set, the event will override the waiting room's new_users_per_minute property while it is active. If null, the event will inherit it. This can only be set if the event's total_active_users property is also set.
	// If set, the event will override the waiting room's `new_users_per_minute` property while it is active. If null, the event will inherit it. This can only be set if the event's `total_active_users` property is also set.
	NewUsersPerMinute *float64 `json:"newUsersPerMinute,omitempty" tf:"new_users_per_minute,omitempty"`

	// (String) An ISO 8601 timestamp that marks when to begin queueing all users before the event starts. The prequeue must start at least five minutes before event_start_time.
	// An ISO 8601 timestamp that marks when to begin queueing all users before the event starts. The prequeue must start at least five minutes before `event_start_time`.
	PrequeueStartTime *string `json:"prequeueStartTime,omitempty" tf:"prequeue_start_time,omitempty"`

	// (String) If set, the event will override the waiting room's queueing_method property while it is active. If null, the event will inherit it.
	// If set, the event will override the waiting room's `queueing_method` property while it is active. If null, the event will inherit it.
	QueueingMethod *string `json:"queueingMethod,omitempty" tf:"queueing_method,omitempty"`

	// (Number) If set, the event will override the waiting room's session_duration property while it is active. If null, the event will inherit it.
	// If set, the event will override the waiting room's `session_duration` property while it is active. If null, the event will inherit it.
	SessionDuration *float64 `json:"sessionDuration,omitempty" tf:"session_duration,omitempty"`

	// (Boolean) If enabled, users in the prequeue will be shuffled randomly at the event_start_time. Requires that prequeue_start_time is not null. This is useful for situations when many users will join the event prequeue at the same time and you want to shuffle them to ensure fairness. Naturally, it makes the most sense to enable this feature when the queueing_method during the event respects ordering such as fifo, or else the shuffling may be unnecessary.
	// If enabled, users in the prequeue will be shuffled randomly at the `event_start_time`. Requires that `prequeue_start_time` is not null. This is useful for situations when many users will join the event prequeue at the same time and you want to shuffle them to ensure fairness. Naturally, it makes the most sense to enable this feature when the `queueing_method` during the event respects ordering such as **fifo**, or else the shuffling may be unnecessary.
	ShuffleAtEventStart *bool `json:"shuffleAtEventStart,omitempty" tf:"shuffle_at_event_start,omitempty"`

	// (Boolean) Suspends or allows an event. If set to true, the event is ignored and traffic will be handled based on the waiting room configuration.
	// Suspends or allows an event. If set to `true`, the event is ignored and traffic will be handled based on the waiting room configuration.
	Suspended *bool `json:"suspended,omitempty" tf:"suspended,omitempty"`

	// (Number) If set, the event will override the waiting room's total_active_users property while it is active. If null, the event will inherit it. This can only be set if the event's new_users_per_minute property is also set.
	// If set, the event will override the waiting room's `total_active_users` property while it is active. If null, the event will inherit it. This can only be set if the event's `new_users_per_minute` property is also set.
	TotalActiveUsers *float64 `json:"totalActiveUsers,omitempty" tf:"total_active_users,omitempty"`

	// (String)
	WaitingRoomID *string `json:"waitingRoomId,omitempty" tf:"waiting_room_id,omitempty"`

	// (String) Identifier
	// Identifier
	ZoneID *string `json:"zoneId,omitempty" tf:"zone_id,omitempty"`
}

type RoomEventParameters struct {

	// (String) If set, the event will override the waiting room's custom_page_html property while it is active. If null, the event will inherit it.
	// If set, the event will override the waiting room's `custom_page_html` property while it is active. If null, the event will inherit it.
	// +kubebuilder:validation:Optional
	CustomPageHTML *string `json:"customPageHtml,omitempty" tf:"custom_page_html,omitempty"`

	// (String) A note that you can use to add more details about the event.
	// A note that you can use to add more details about the event.
	// +kubebuilder:validation:Optional
	Description *string `json:"description,omitempty" tf:"description,omitempty"`

	// (Boolean) If set, the event will override the waiting room's disable_session_renewal property while it is active. If null, the event will inherit it.
	// If set, the event will override the waiting room's `disable_session_renewal` property while it is active. If null, the event will inherit it.
	// +kubebuilder:validation:Optional
	DisableSessionRenewal *bool `json:"disableSessionRenewal,omitempty" tf:"disable_session_renewal,omitempty"`

	// (String) An ISO 8601 timestamp that marks the end of the event.
	// An ISO 8601 timestamp that marks the end of the event.
	// +kubebuilder:validation:Optional
	EventEndTime *string `json:"eventEndTime,omitempty" tf:"event_end_time,omitempty"`

	// (String) An ISO 8601 timestamp that marks the start of the event. At this time, queued users will be processed with the event's configuration. The start time must be at least one minute before event_end_time.
	// An ISO 8601 timestamp that marks the start of the event. At this time, queued users will be processed with the event's configuration. The start time must be at least one minute before `event_end_time`.
	// +kubebuilder:validation:Optional
	EventStartTime *string `json:"eventStartTime,omitempty" tf:"event_start_time,omitempty"`

	// (Number) If set, the event will override the waiting room's new_users_per_minute property while it is active. If null, the event will inherit it. This can only be set if the event's total_active_users property is also set.
	// If set, the event will override the waiting room's `new_users_per_minute` property while it is active. If null, the event will inherit it. This can only be set if the event's `total_active_users` property is also set.
	// +kubebuilder:validation:Optional
	NewUsersPerMinute *float64 `json:"newUsersPerMinute,omitempty" tf:"new_users_per_minute,omitempty"`

	// (String) An ISO 8601 timestamp that marks when to begin queueing all users before the event starts. The prequeue must start at least five minutes before event_start_time.
	// An ISO 8601 timestamp that marks when to begin queueing all users before the event starts. The prequeue must start at least five minutes before `event_start_time`.
	// +kubebuilder:validation:Optional
	PrequeueStartTime *string `json:"prequeueStartTime,omitempty" tf:"prequeue_start_time,omitempty"`

	// (String) If set, the event will override the waiting room's queueing_method property while it is active. If null, the event will inherit it.
	// If set, the event will override the waiting room's `queueing_method` property while it is active. If null, the event will inherit it.
	// +kubebuilder:validation:Optional
	QueueingMethod *string `json:"queueingMethod,omitempty" tf:"queueing_method,omitempty"`

	// (Number) If set, the event will override the waiting room's session_duration property while it is active. If null, the event will inherit it.
	// If set, the event will override the waiting room's `session_duration` property while it is active. If null, the event will inherit it.
	// +kubebuilder:validation:Optional
	SessionDuration *float64 `json:"sessionDuration,omitempty" tf:"session_duration,omitempty"`

	// (Boolean) If enabled, users in the prequeue will be shuffled randomly at the event_start_time. Requires that prequeue_start_time is not null. This is useful for situations when many users will join the event prequeue at the same time and you want to shuffle them to ensure fairness. Naturally, it makes the most sense to enable this feature when the queueing_method during the event respects ordering such as fifo, or else the shuffling may be unnecessary.
	// If enabled, users in the prequeue will be shuffled randomly at the `event_start_time`. Requires that `prequeue_start_time` is not null. This is useful for situations when many users will join the event prequeue at the same time and you want to shuffle them to ensure fairness. Naturally, it makes the most sense to enable this feature when the `queueing_method` during the event respects ordering such as **fifo**, or else the shuffling may be unnecessary.
	// +kubebuilder:validation:Optional
	ShuffleAtEventStart *bool `json:"shuffleAtEventStart,omitempty" tf:"shuffle_at_event_start,omitempty"`

	// (Boolean) Suspends or allows an event. If set to true, the event is ignored and traffic will be handled based on the waiting room configuration.
	// Suspends or allows an event. If set to `true`, the event is ignored and traffic will be handled based on the waiting room configuration.
	// +kubebuilder:validation:Optional
	Suspended *bool `json:"suspended,omitempty" tf:"suspended,omitempty"`

	// (Number) If set, the event will override the waiting room's total_active_users property while it is active. If null, the event will inherit it. This can only be set if the event's new_users_per_minute property is also set.
	// If set, the event will override the waiting room's `total_active_users` property while it is active. If null, the event will inherit it. This can only be set if the event's `new_users_per_minute` property is also set.
	// +kubebuilder:validation:Optional
	TotalActiveUsers *float64 `json:"totalActiveUsers,omitempty" tf:"total_active_users,omitempty"`

	// (String)
	// +kubebuilder:validation:Optional
	WaitingRoomID *string `json:"waitingRoomId,omitempty" tf:"waiting_room_id,omitempty"`

	// (String) Identifier
	// Identifier
	// +kubebuilder:validation:Optional
	ZoneID *string `json:"zoneId,omitempty" tf:"zone_id,omitempty"`
}

// RoomEventSpec defines the desired state of RoomEvent
type RoomEventSpec struct {
	v1.ResourceSpec `json:",inline"`
	ForProvider     RoomEventParameters `json:"forProvider"`
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
	InitProvider RoomEventInitParameters `json:"initProvider,omitempty"`
}

// RoomEventStatus defines the observed state of RoomEvent.
type RoomEventStatus struct {
	v1.ResourceStatus `json:",inline"`
	AtProvider        RoomEventObservation `json:"atProvider,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:storageversion

// RoomEvent is the Schema for the RoomEvents API.
// +kubebuilder:printcolumn:name="SYNCED",type="string",JSONPath=".status.conditions[?(@.type=='Synced')].status"
// +kubebuilder:printcolumn:name="READY",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="EXTERNAL-NAME",type="string",JSONPath=".metadata.annotations.crossplane\\.io/external-name"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:resource:scope=Cluster,categories={crossplane,managed,cloudflare}
type RoomEvent struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.eventEndTime) || (has(self.initProvider) && has(self.initProvider.eventEndTime))",message="spec.forProvider.eventEndTime is a required parameter"
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.eventStartTime) || (has(self.initProvider) && has(self.initProvider.eventStartTime))",message="spec.forProvider.eventStartTime is a required parameter"
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.waitingRoomId) || (has(self.initProvider) && has(self.initProvider.waitingRoomId))",message="spec.forProvider.waitingRoomId is a required parameter"
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.zoneId) || (has(self.initProvider) && has(self.initProvider.zoneId))",message="spec.forProvider.zoneId is a required parameter"
	Spec   RoomEventSpec   `json:"spec"`
	Status RoomEventStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// RoomEventList contains a list of RoomEvents
type RoomEventList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []RoomEvent `json:"items"`
}

// Repository type metadata.
var (
	RoomEvent_Kind             = "RoomEvent"
	RoomEvent_GroupKind        = schema.GroupKind{Group: CRDGroup, Kind: RoomEvent_Kind}.String()
	RoomEvent_KindAPIVersion   = RoomEvent_Kind + "." + CRDGroupVersion.String()
	RoomEvent_GroupVersionKind = CRDGroupVersion.WithKind(RoomEvent_Kind)
)

func init() {
	SchemeBuilder.Register(&RoomEvent{}, &RoomEventList{})
}
