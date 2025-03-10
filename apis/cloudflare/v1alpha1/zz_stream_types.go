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

type InputInitParameters struct {
}

type InputObservation struct {

	// 1 means the height is unknown. The value becomes available after the upload and before the video is ready.
	// The video height in pixels. A value of `-1` means the height is unknown. The value becomes available after the upload and before the video is ready.
	Height *float64 `json:"height,omitempty" tf:"height,omitempty"`

	// 1 means the width is unknown. The value becomes available after the upload and before the video is ready.
	// The video width in pixels. A value of `-1` means the width is unknown. The value becomes available after the upload and before the video is ready.
	Width *float64 `json:"width,omitempty" tf:"width,omitempty"`
}

type InputParameters struct {
}

type PlaybackInitParameters struct {
}

type PlaybackObservation struct {

	// (String) DASH Media Presentation Description for the video.
	// DASH Media Presentation Description for the video.
	Dash *string `json:"dash,omitempty" tf:"dash,omitempty"`

	// (String) The HLS manifest for the video.
	// The HLS manifest for the video.
	Hls *string `json:"hls,omitempty" tf:"hls,omitempty"`
}

type PlaybackParameters struct {
}

type StatusInitParameters struct {
}

type StatusObservation struct {

	// (String) Specifies why the video failed to encode. This field is empty if the video is not in an error state. Preferred for programmatic use.
	// Specifies why the video failed to encode. This field is empty if the video is not in an `error` state. Preferred for programmatic use.
	ErrorReasonCode *string `json:"errorReasonCode,omitempty" tf:"error_reason_code,omitempty"`

	// (String) Specifies why the video failed to encode using a human readable error message in English. This field is empty if the video is not in an error state.
	// Specifies why the video failed to encode using a human readable error message in English. This field is empty if the video is not in an `error` state.
	ErrorReasonText *string `json:"errorReasonText,omitempty" tf:"error_reason_text,omitempty"`

	// negative integer.
	// Indicates the size of the entire upload in bytes. The value must be a non-negative integer.
	PctComplete *string `json:"pctComplete,omitempty" tf:"pct_complete,omitempty"`

	// (String) Specifies the processing status for all quality levels for a video.
	// Specifies the processing status for all quality levels for a video.
	State *string `json:"state,omitempty" tf:"state,omitempty"`
}

type StatusParameters struct {
}

type StreamInitParameters struct {

	// (String) The account identifier tag.
	// The account identifier tag.
	AccountID *string `json:"accountId,omitempty" tf:"account_id,omitempty"`

	// (List of String) Lists the origins allowed to display the video. Enter allowed origin domains in an array and use * for wildcard subdomains. Empty arrays allow the video to be viewed on any origin.
	// Lists the origins allowed to display the video. Enter allowed origin domains in an array and use `*` for wildcard subdomains. Empty arrays allow the video to be viewed on any origin.
	AllowedOrigins []*string `json:"allowedOrigins,omitempty" tf:"allowed_origins,omitempty"`

	// defined identifier for the media creator.
	// A user-defined identifier for the media creator.
	Creator *string `json:"creator,omitempty" tf:"creator,omitempty"`

	// generated unique identifier for a media item.
	// A Cloudflare-generated unique identifier for a media item.
	Identifier *string `json:"identifier,omitempty" tf:"identifier,omitempty"`

	// (Attributes) (see below for nested schema)
	Input *InputInitParameters `json:"input,omitempty" tf:"input,omitempty"`

	// 1 means the value is unknown.
	// The maximum duration in seconds for a video upload. Can be set for a video that is not yet uploaded to limit its duration. Uploads that exceed the specified duration will fail during processing. A value of `-1` means the value is unknown.
	MaxDurationSeconds *float64 `json:"maxDurationSeconds,omitempty" tf:"max_duration_seconds,omitempty"`

	// value store used to reference other systems of record for managing videos.
	// A user modifiable key-value store used to reference other systems of record for managing videos.
	Meta *string `json:"meta,omitempty" tf:"meta,omitempty"`

	// (Attributes) (see below for nested schema)
	Playback *PlaybackInitParameters `json:"playback,omitempty" tf:"playback,omitempty"`

	// (Boolean) Indicates whether the video can be a accessed using the UID. When set to true, a signed token must be generated with a signing key to view the video.
	// Indicates whether the video can be a accessed using the UID. When set to `true`, a signed token must be generated with a signing key to view the video.
	RequireSignedUrls *bool `json:"requireSignedUrls,omitempty" tf:"require_signed_urls,omitempty"`

	// (String) Indicates the date and time at which the video will be deleted. Omit the field to indicate no change, or include with a null value to remove an existing scheduled deletion. If specified, must be at least 30 days from upload time.
	// Indicates the date and time at which the video will be deleted. Omit the field to indicate no change, or include with a `null` value to remove an existing scheduled deletion. If specified, must be at least 30 days from upload time.
	ScheduledDeletion *string `json:"scheduledDeletion,omitempty" tf:"scheduled_deletion,omitempty"`

	// (Attributes) Specifies a detailed status for a video. If the state is inprogress or error, the step field returns encoding or manifest. If the state is inprogress, pctComplete returns a number between 0 and 100 to indicate the approximate percent of completion. If the state is error, errorReasonCode and errorReasonText provide additional details. (see below for nested schema)
	Status *StatusInitParameters `json:"status,omitempty" tf:"status,omitempty"`

	// wise timestamp to a percentage, divide the desired timestamp by the total duration of the video.  If this value is not set, the default thumbnail image is taken from 0s of the video.
	// The timestamp for a thumbnail image calculated as a percentage value of the video's duration. To convert from a second-wise timestamp to a percentage, divide the desired timestamp by the total duration of the video.  If this value is not set, the default thumbnail image is taken from 0s of the video.
	ThumbnailTimestampPct *float64 `json:"thumbnailTimestampPct,omitempty" tf:"thumbnail_timestamp_pct,omitempty"`

	// (String) The date and time when the video upload URL is no longer valid for direct user uploads.
	// The date and time when the video upload URL is no longer valid for direct user uploads.
	UploadExpiry *string `json:"uploadExpiry,omitempty" tf:"upload_expiry,omitempty"`

	// (Attributes) (see below for nested schema)
	Watermark *WatermarkInitParameters `json:"watermark,omitempty" tf:"watermark,omitempty"`
}

type StreamObservation struct {

	// (String) The account identifier tag.
	// The account identifier tag.
	AccountID *string `json:"accountId,omitempty" tf:"account_id,omitempty"`

	// (List of String) Lists the origins allowed to display the video. Enter allowed origin domains in an array and use * for wildcard subdomains. Empty arrays allow the video to be viewed on any origin.
	// Lists the origins allowed to display the video. Enter allowed origin domains in an array and use `*` for wildcard subdomains. Empty arrays allow the video to be viewed on any origin.
	AllowedOrigins []*string `json:"allowedOrigins,omitempty" tf:"allowed_origins,omitempty"`

	// (String) The date and time the media item was created.
	// The date and time the media item was created.
	Created *string `json:"created,omitempty" tf:"created,omitempty"`

	// defined identifier for the media creator.
	// A user-defined identifier for the media creator.
	Creator *string `json:"creator,omitempty" tf:"creator,omitempty"`

	// 1 means the duration is unknown. The duration becomes available after the upload and before the video is ready.
	// The duration of the video in seconds. A value of `-1` means the duration is unknown. The duration becomes available after the upload and before the video is ready.
	Duration *float64 `json:"duration,omitempty" tf:"duration,omitempty"`

	ID *string `json:"id,omitempty" tf:"id,omitempty"`

	// generated unique identifier for a media item.
	// A Cloudflare-generated unique identifier for a media item.
	Identifier *string `json:"identifier,omitempty" tf:"identifier,omitempty"`

	// (Attributes) (see below for nested schema)
	Input *InputObservation `json:"input,omitempty" tf:"input,omitempty"`

	// (String) The live input ID used to upload a video with Stream Live.
	// The live input ID used to upload a video with Stream Live.
	LiveInput *string `json:"liveInput,omitempty" tf:"live_input,omitempty"`

	// 1 means the value is unknown.
	// The maximum duration in seconds for a video upload. Can be set for a video that is not yet uploaded to limit its duration. Uploads that exceed the specified duration will fail during processing. A value of `-1` means the value is unknown.
	MaxDurationSeconds *float64 `json:"maxDurationSeconds,omitempty" tf:"max_duration_seconds,omitempty"`

	// value store used to reference other systems of record for managing videos.
	// A user modifiable key-value store used to reference other systems of record for managing videos.
	Meta *string `json:"meta,omitempty" tf:"meta,omitempty"`

	// (String) The date and time the media item was last modified.
	// The date and time the media item was last modified.
	Modified *string `json:"modified,omitempty" tf:"modified,omitempty"`

	// (Attributes) (see below for nested schema)
	Playback *PlaybackObservation `json:"playback,omitempty" tf:"playback,omitempty"`

	// (String) The video's preview page URI. This field is omitted until encoding is complete.
	// The video's preview page URI. This field is omitted until encoding is complete.
	Preview *string `json:"preview,omitempty" tf:"preview,omitempty"`

	// (Boolean) Indicates whether the video is playable. The field is empty if the video is not ready for viewing or the live stream is still in progress.
	// Indicates whether the video is playable. The field is empty if the video is not ready for viewing or the live stream is still in progress.
	ReadyToStream *bool `json:"readyToStream,omitempty" tf:"ready_to_stream,omitempty"`

	// (String) Indicates the time at which the video became playable. The field is empty if the video is not ready for viewing or the live stream is still in progress.
	// Indicates the time at which the video became playable. The field is empty if the video is not ready for viewing or the live stream is still in progress.
	ReadyToStreamAt *string `json:"readyToStreamAt,omitempty" tf:"ready_to_stream_at,omitempty"`

	// (Boolean) Indicates whether the video can be a accessed using the UID. When set to true, a signed token must be generated with a signing key to view the video.
	// Indicates whether the video can be a accessed using the UID. When set to `true`, a signed token must be generated with a signing key to view the video.
	RequireSignedUrls *bool `json:"requireSignedUrls,omitempty" tf:"require_signed_urls,omitempty"`

	// (String) Indicates the date and time at which the video will be deleted. Omit the field to indicate no change, or include with a null value to remove an existing scheduled deletion. If specified, must be at least 30 days from upload time.
	// Indicates the date and time at which the video will be deleted. Omit the field to indicate no change, or include with a `null` value to remove an existing scheduled deletion. If specified, must be at least 30 days from upload time.
	ScheduledDeletion *string `json:"scheduledDeletion,omitempty" tf:"scheduled_deletion,omitempty"`

	// (Number) The size of the media item in bytes.
	// The size of the media item in bytes.
	Size *float64 `json:"size,omitempty" tf:"size,omitempty"`

	// (Attributes) Specifies a detailed status for a video. If the state is inprogress or error, the step field returns encoding or manifest. If the state is inprogress, pctComplete returns a number between 0 and 100 to indicate the approximate percent of completion. If the state is error, errorReasonCode and errorReasonText provide additional details. (see below for nested schema)
	Status *StatusObservation `json:"status,omitempty" tf:"status,omitempty"`

	// (String) The media item's thumbnail URI. This field is omitted until encoding is complete.
	// The media item's thumbnail URI. This field is omitted until encoding is complete.
	Thumbnail *string `json:"thumbnail,omitempty" tf:"thumbnail,omitempty"`

	// wise timestamp to a percentage, divide the desired timestamp by the total duration of the video.  If this value is not set, the default thumbnail image is taken from 0s of the video.
	// The timestamp for a thumbnail image calculated as a percentage value of the video's duration. To convert from a second-wise timestamp to a percentage, divide the desired timestamp by the total duration of the video.  If this value is not set, the default thumbnail image is taken from 0s of the video.
	ThumbnailTimestampPct *float64 `json:"thumbnailTimestampPct,omitempty" tf:"thumbnail_timestamp_pct,omitempty"`

	// generated unique identifier for a media item.
	// A Cloudflare-generated unique identifier for a media item.
	UID *string `json:"uid,omitempty" tf:"uid,omitempty"`

	// (String) The date and time when the video upload URL is no longer valid for direct user uploads.
	// The date and time when the video upload URL is no longer valid for direct user uploads.
	UploadExpiry *string `json:"uploadExpiry,omitempty" tf:"upload_expiry,omitempty"`

	// (String) The date and time the media item was uploaded.
	// The date and time the media item was uploaded.
	Uploaded *string `json:"uploaded,omitempty" tf:"uploaded,omitempty"`

	// (Attributes) (see below for nested schema)
	Watermark *WatermarkObservation `json:"watermark,omitempty" tf:"watermark,omitempty"`
}

type StreamParameters struct {

	// (String) The account identifier tag.
	// The account identifier tag.
	// +kubebuilder:validation:Optional
	AccountID *string `json:"accountId,omitempty" tf:"account_id,omitempty"`

	// (List of String) Lists the origins allowed to display the video. Enter allowed origin domains in an array and use * for wildcard subdomains. Empty arrays allow the video to be viewed on any origin.
	// Lists the origins allowed to display the video. Enter allowed origin domains in an array and use `*` for wildcard subdomains. Empty arrays allow the video to be viewed on any origin.
	// +kubebuilder:validation:Optional
	AllowedOrigins []*string `json:"allowedOrigins,omitempty" tf:"allowed_origins,omitempty"`

	// defined identifier for the media creator.
	// A user-defined identifier for the media creator.
	// +kubebuilder:validation:Optional
	Creator *string `json:"creator,omitempty" tf:"creator,omitempty"`

	// generated unique identifier for a media item.
	// A Cloudflare-generated unique identifier for a media item.
	// +kubebuilder:validation:Optional
	Identifier *string `json:"identifier,omitempty" tf:"identifier,omitempty"`

	// (Attributes) (see below for nested schema)
	// +kubebuilder:validation:Optional
	Input *InputParameters `json:"input,omitempty" tf:"input,omitempty"`

	// 1 means the value is unknown.
	// The maximum duration in seconds for a video upload. Can be set for a video that is not yet uploaded to limit its duration. Uploads that exceed the specified duration will fail during processing. A value of `-1` means the value is unknown.
	// +kubebuilder:validation:Optional
	MaxDurationSeconds *float64 `json:"maxDurationSeconds,omitempty" tf:"max_duration_seconds,omitempty"`

	// value store used to reference other systems of record for managing videos.
	// A user modifiable key-value store used to reference other systems of record for managing videos.
	// +kubebuilder:validation:Optional
	Meta *string `json:"meta,omitempty" tf:"meta,omitempty"`

	// (Attributes) (see below for nested schema)
	// +kubebuilder:validation:Optional
	Playback *PlaybackParameters `json:"playback,omitempty" tf:"playback,omitempty"`

	// (Boolean) Indicates whether the video can be a accessed using the UID. When set to true, a signed token must be generated with a signing key to view the video.
	// Indicates whether the video can be a accessed using the UID. When set to `true`, a signed token must be generated with a signing key to view the video.
	// +kubebuilder:validation:Optional
	RequireSignedUrls *bool `json:"requireSignedUrls,omitempty" tf:"require_signed_urls,omitempty"`

	// (String) Indicates the date and time at which the video will be deleted. Omit the field to indicate no change, or include with a null value to remove an existing scheduled deletion. If specified, must be at least 30 days from upload time.
	// Indicates the date and time at which the video will be deleted. Omit the field to indicate no change, or include with a `null` value to remove an existing scheduled deletion. If specified, must be at least 30 days from upload time.
	// +kubebuilder:validation:Optional
	ScheduledDeletion *string `json:"scheduledDeletion,omitempty" tf:"scheduled_deletion,omitempty"`

	// (Attributes) Specifies a detailed status for a video. If the state is inprogress or error, the step field returns encoding or manifest. If the state is inprogress, pctComplete returns a number between 0 and 100 to indicate the approximate percent of completion. If the state is error, errorReasonCode and errorReasonText provide additional details. (see below for nested schema)
	// +kubebuilder:validation:Optional
	Status *StatusParameters `json:"status,omitempty" tf:"status,omitempty"`

	// wise timestamp to a percentage, divide the desired timestamp by the total duration of the video.  If this value is not set, the default thumbnail image is taken from 0s of the video.
	// The timestamp for a thumbnail image calculated as a percentage value of the video's duration. To convert from a second-wise timestamp to a percentage, divide the desired timestamp by the total duration of the video.  If this value is not set, the default thumbnail image is taken from 0s of the video.
	// +kubebuilder:validation:Optional
	ThumbnailTimestampPct *float64 `json:"thumbnailTimestampPct,omitempty" tf:"thumbnail_timestamp_pct,omitempty"`

	// (String) The date and time when the video upload URL is no longer valid for direct user uploads.
	// The date and time when the video upload URL is no longer valid for direct user uploads.
	// +kubebuilder:validation:Optional
	UploadExpiry *string `json:"uploadExpiry,omitempty" tf:"upload_expiry,omitempty"`

	// (Attributes) (see below for nested schema)
	// +kubebuilder:validation:Optional
	Watermark *WatermarkParameters `json:"watermark,omitempty" tf:"watermark,omitempty"`
}

type WatermarkInitParameters struct {
}

type WatermarkObservation struct {

	// (String) The date and time the media item was created.
	// The date and a time a watermark profile was created.
	Created *string `json:"created,omitempty" tf:"created,omitempty"`

	// (String) The source URL for a downloaded image. If the watermark profile was created via direct upload, this field is null.
	// The source URL for a downloaded image. If the watermark profile was created via direct upload, this field is null.
	DownloadedFrom *string `json:"downloadedFrom,omitempty" tf:"downloaded_from,omitempty"`

	// 1 means the height is unknown. The value becomes available after the upload and before the video is ready.
	// The height of the image in pixels.
	Height *float64 `json:"height,omitempty" tf:"height,omitempty"`

	// (String) A short description of the watermark profile.
	// A short description of the watermark profile.
	Name *string `json:"name,omitempty" tf:"name,omitempty"`

	// transparent, setting this to 1.0 will not make the image completely opaque.
	// The translucency of the image. A value of `0.0` makes the image completely transparent, and `1.0` makes the image completely opaque. Note that if the image is already semi-transparent, setting this to `1.0` will not make the image completely opaque.
	Opacity *float64 `json:"opacity,omitempty" tf:"opacity,omitempty"`

	// (Number) The whitespace between the adjacent edges (determined by position) of the video and the image. 0.0 indicates no padding, and 1.0 indicates a fully padded video width or length, as determined by the algorithm.
	// The whitespace between the adjacent edges (determined by position) of the video and the image. `0.0` indicates no padding, and `1.0` indicates a fully padded video width or length, as determined by the algorithm.
	Padding *float64 `json:"padding,omitempty" tf:"padding,omitempty"`

	// (String) The location of the image. Valid positions are: upperRight, upperLeft, lowerLeft, lowerRight, and center. Note that center ignores the padding parameter.
	// The location of the image. Valid positions are: `upperRight`, `upperLeft`, `lowerLeft`, `lowerRight`, and `center`. Note that `center` ignores the `padding` parameter.
	Position *string `json:"position,omitempty" tf:"position,omitempty"`

	// is), and 1.0 fills the entire video.
	// The size of the image relative to the overall size of the video. This parameter will adapt to horizontal and vertical videos automatically. `0.0` indicates no scaling (use the size of the image as-is), and `1.0 `fills the entire video.
	Scale *float64 `json:"scale,omitempty" tf:"scale,omitempty"`

	// (Number) The size of the media item in bytes.
	// The size of the image in bytes.
	Size *float64 `json:"size,omitempty" tf:"size,omitempty"`

	// generated unique identifier for a media item.
	// The unique identifier for a watermark profile.
	UID *string `json:"uid,omitempty" tf:"uid,omitempty"`

	// 1 means the width is unknown. The value becomes available after the upload and before the video is ready.
	// The width of the image in pixels.
	Width *float64 `json:"width,omitempty" tf:"width,omitempty"`
}

type WatermarkParameters struct {
}

// StreamSpec defines the desired state of Stream
type StreamSpec struct {
	v1.ResourceSpec `json:",inline"`
	ForProvider     StreamParameters `json:"forProvider"`
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
	InitProvider StreamInitParameters `json:"initProvider,omitempty"`
}

// StreamStatus defines the observed state of Stream.
type StreamStatus struct {
	v1.ResourceStatus `json:",inline"`
	AtProvider        StreamObservation `json:"atProvider,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:storageversion

// Stream is the Schema for the Streams API.
// +kubebuilder:printcolumn:name="SYNCED",type="string",JSONPath=".status.conditions[?(@.type=='Synced')].status"
// +kubebuilder:printcolumn:name="READY",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="EXTERNAL-NAME",type="string",JSONPath=".metadata.annotations.crossplane\\.io/external-name"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:resource:scope=Cluster,categories={crossplane,managed,cloudflare}
type Stream struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.accountId) || (has(self.initProvider) && has(self.initProvider.accountId))",message="spec.forProvider.accountId is a required parameter"
	Spec   StreamSpec   `json:"spec"`
	Status StreamStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// StreamList contains a list of Streams
type StreamList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Stream `json:"items"`
}

// Repository type metadata.
var (
	Stream_Kind             = "Stream"
	Stream_GroupKind        = schema.GroupKind{Group: CRDGroup, Kind: Stream_Kind}.String()
	Stream_KindAPIVersion   = Stream_Kind + "." + CRDGroupVersion.String()
	Stream_GroupVersionKind = CRDGroupVersion.WithKind(Stream_Kind)
)

func init() {
	SchemeBuilder.Register(&Stream{}, &StreamList{})
}
