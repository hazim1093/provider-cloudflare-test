//go:build !ignore_autogenerated

// SPDX-FileCopyrightText: 2024 The Crossplane Authors <https://crossplane.io>
//
// SPDX-License-Identifier: Apache-2.0

// Code generated by controller-gen. DO NOT EDIT.

package v1alpha1

import (
	runtime "k8s.io/apimachinery/pkg/runtime"
)

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *Consumer) DeepCopyInto(out *Consumer) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new Consumer.
func (in *Consumer) DeepCopy() *Consumer {
	if in == nil {
		return nil
	}
	out := new(Consumer)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *Consumer) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ConsumerInitParameters) DeepCopyInto(out *ConsumerInitParameters) {
	*out = *in
	if in.AccountID != nil {
		in, out := &in.AccountID, &out.AccountID
		*out = new(string)
		**out = **in
	}
	if in.ConsumerID != nil {
		in, out := &in.ConsumerID, &out.ConsumerID
		*out = new(string)
		**out = **in
	}
	if in.DeadLetterQueue != nil {
		in, out := &in.DeadLetterQueue, &out.DeadLetterQueue
		*out = new(string)
		**out = **in
	}
	if in.QueueID != nil {
		in, out := &in.QueueID, &out.QueueID
		*out = new(string)
		**out = **in
	}
	if in.ScriptName != nil {
		in, out := &in.ScriptName, &out.ScriptName
		*out = new(string)
		**out = **in
	}
	if in.Settings != nil {
		in, out := &in.Settings, &out.Settings
		*out = new(SettingsInitParameters)
		(*in).DeepCopyInto(*out)
	}
	if in.Type != nil {
		in, out := &in.Type, &out.Type
		*out = new(string)
		**out = **in
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ConsumerInitParameters.
func (in *ConsumerInitParameters) DeepCopy() *ConsumerInitParameters {
	if in == nil {
		return nil
	}
	out := new(ConsumerInitParameters)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ConsumerList) DeepCopyInto(out *ConsumerList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]Consumer, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ConsumerList.
func (in *ConsumerList) DeepCopy() *ConsumerList {
	if in == nil {
		return nil
	}
	out := new(ConsumerList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *ConsumerList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ConsumerObservation) DeepCopyInto(out *ConsumerObservation) {
	*out = *in
	if in.AccountID != nil {
		in, out := &in.AccountID, &out.AccountID
		*out = new(string)
		**out = **in
	}
	if in.ConsumerID != nil {
		in, out := &in.ConsumerID, &out.ConsumerID
		*out = new(string)
		**out = **in
	}
	if in.CreatedOn != nil {
		in, out := &in.CreatedOn, &out.CreatedOn
		*out = new(string)
		**out = **in
	}
	if in.DeadLetterQueue != nil {
		in, out := &in.DeadLetterQueue, &out.DeadLetterQueue
		*out = new(string)
		**out = **in
	}
	if in.ID != nil {
		in, out := &in.ID, &out.ID
		*out = new(string)
		**out = **in
	}
	if in.QueueID != nil {
		in, out := &in.QueueID, &out.QueueID
		*out = new(string)
		**out = **in
	}
	if in.Script != nil {
		in, out := &in.Script, &out.Script
		*out = new(string)
		**out = **in
	}
	if in.ScriptName != nil {
		in, out := &in.ScriptName, &out.ScriptName
		*out = new(string)
		**out = **in
	}
	if in.Settings != nil {
		in, out := &in.Settings, &out.Settings
		*out = new(SettingsObservation)
		(*in).DeepCopyInto(*out)
	}
	if in.Type != nil {
		in, out := &in.Type, &out.Type
		*out = new(string)
		**out = **in
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ConsumerObservation.
func (in *ConsumerObservation) DeepCopy() *ConsumerObservation {
	if in == nil {
		return nil
	}
	out := new(ConsumerObservation)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ConsumerParameters) DeepCopyInto(out *ConsumerParameters) {
	*out = *in
	if in.AccountID != nil {
		in, out := &in.AccountID, &out.AccountID
		*out = new(string)
		**out = **in
	}
	if in.ConsumerID != nil {
		in, out := &in.ConsumerID, &out.ConsumerID
		*out = new(string)
		**out = **in
	}
	if in.DeadLetterQueue != nil {
		in, out := &in.DeadLetterQueue, &out.DeadLetterQueue
		*out = new(string)
		**out = **in
	}
	if in.QueueID != nil {
		in, out := &in.QueueID, &out.QueueID
		*out = new(string)
		**out = **in
	}
	if in.ScriptName != nil {
		in, out := &in.ScriptName, &out.ScriptName
		*out = new(string)
		**out = **in
	}
	if in.Settings != nil {
		in, out := &in.Settings, &out.Settings
		*out = new(SettingsParameters)
		(*in).DeepCopyInto(*out)
	}
	if in.Type != nil {
		in, out := &in.Type, &out.Type
		*out = new(string)
		**out = **in
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ConsumerParameters.
func (in *ConsumerParameters) DeepCopy() *ConsumerParameters {
	if in == nil {
		return nil
	}
	out := new(ConsumerParameters)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ConsumerSpec) DeepCopyInto(out *ConsumerSpec) {
	*out = *in
	in.ResourceSpec.DeepCopyInto(&out.ResourceSpec)
	in.ForProvider.DeepCopyInto(&out.ForProvider)
	in.InitProvider.DeepCopyInto(&out.InitProvider)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ConsumerSpec.
func (in *ConsumerSpec) DeepCopy() *ConsumerSpec {
	if in == nil {
		return nil
	}
	out := new(ConsumerSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ConsumerStatus) DeepCopyInto(out *ConsumerStatus) {
	*out = *in
	in.ResourceStatus.DeepCopyInto(&out.ResourceStatus)
	in.AtProvider.DeepCopyInto(&out.AtProvider)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ConsumerStatus.
func (in *ConsumerStatus) DeepCopy() *ConsumerStatus {
	if in == nil {
		return nil
	}
	out := new(ConsumerStatus)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *SettingsInitParameters) DeepCopyInto(out *SettingsInitParameters) {
	*out = *in
	if in.BatchSize != nil {
		in, out := &in.BatchSize, &out.BatchSize
		*out = new(float64)
		**out = **in
	}
	if in.MaxConcurrency != nil {
		in, out := &in.MaxConcurrency, &out.MaxConcurrency
		*out = new(float64)
		**out = **in
	}
	if in.MaxRetries != nil {
		in, out := &in.MaxRetries, &out.MaxRetries
		*out = new(float64)
		**out = **in
	}
	if in.MaxWaitTimeMs != nil {
		in, out := &in.MaxWaitTimeMs, &out.MaxWaitTimeMs
		*out = new(float64)
		**out = **in
	}
	if in.RetryDelay != nil {
		in, out := &in.RetryDelay, &out.RetryDelay
		*out = new(float64)
		**out = **in
	}
	if in.VisibilityTimeoutMs != nil {
		in, out := &in.VisibilityTimeoutMs, &out.VisibilityTimeoutMs
		*out = new(float64)
		**out = **in
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new SettingsInitParameters.
func (in *SettingsInitParameters) DeepCopy() *SettingsInitParameters {
	if in == nil {
		return nil
	}
	out := new(SettingsInitParameters)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *SettingsObservation) DeepCopyInto(out *SettingsObservation) {
	*out = *in
	if in.BatchSize != nil {
		in, out := &in.BatchSize, &out.BatchSize
		*out = new(float64)
		**out = **in
	}
	if in.MaxConcurrency != nil {
		in, out := &in.MaxConcurrency, &out.MaxConcurrency
		*out = new(float64)
		**out = **in
	}
	if in.MaxRetries != nil {
		in, out := &in.MaxRetries, &out.MaxRetries
		*out = new(float64)
		**out = **in
	}
	if in.MaxWaitTimeMs != nil {
		in, out := &in.MaxWaitTimeMs, &out.MaxWaitTimeMs
		*out = new(float64)
		**out = **in
	}
	if in.RetryDelay != nil {
		in, out := &in.RetryDelay, &out.RetryDelay
		*out = new(float64)
		**out = **in
	}
	if in.VisibilityTimeoutMs != nil {
		in, out := &in.VisibilityTimeoutMs, &out.VisibilityTimeoutMs
		*out = new(float64)
		**out = **in
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new SettingsObservation.
func (in *SettingsObservation) DeepCopy() *SettingsObservation {
	if in == nil {
		return nil
	}
	out := new(SettingsObservation)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *SettingsParameters) DeepCopyInto(out *SettingsParameters) {
	*out = *in
	if in.BatchSize != nil {
		in, out := &in.BatchSize, &out.BatchSize
		*out = new(float64)
		**out = **in
	}
	if in.MaxConcurrency != nil {
		in, out := &in.MaxConcurrency, &out.MaxConcurrency
		*out = new(float64)
		**out = **in
	}
	if in.MaxRetries != nil {
		in, out := &in.MaxRetries, &out.MaxRetries
		*out = new(float64)
		**out = **in
	}
	if in.MaxWaitTimeMs != nil {
		in, out := &in.MaxWaitTimeMs, &out.MaxWaitTimeMs
		*out = new(float64)
		**out = **in
	}
	if in.RetryDelay != nil {
		in, out := &in.RetryDelay, &out.RetryDelay
		*out = new(float64)
		**out = **in
	}
	if in.VisibilityTimeoutMs != nil {
		in, out := &in.VisibilityTimeoutMs, &out.VisibilityTimeoutMs
		*out = new(float64)
		**out = **in
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new SettingsParameters.
func (in *SettingsParameters) DeepCopy() *SettingsParameters {
	if in == nil {
		return nil
	}
	out := new(SettingsParameters)
	in.DeepCopyInto(out)
	return out
}
