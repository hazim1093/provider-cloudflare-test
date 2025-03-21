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
func (in *HostnameInitParameters) DeepCopyInto(out *HostnameInitParameters) {
	*out = *in
	if in.URLHostname != nil {
		in, out := &in.URLHostname, &out.URLHostname
		*out = new(string)
		**out = **in
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new HostnameInitParameters.
func (in *HostnameInitParameters) DeepCopy() *HostnameInitParameters {
	if in == nil {
		return nil
	}
	out := new(HostnameInitParameters)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *HostnameObservation) DeepCopyInto(out *HostnameObservation) {
	*out = *in
	if in.URLHostname != nil {
		in, out := &in.URLHostname, &out.URLHostname
		*out = new(string)
		**out = **in
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new HostnameObservation.
func (in *HostnameObservation) DeepCopy() *HostnameObservation {
	if in == nil {
		return nil
	}
	out := new(HostnameObservation)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *HostnameParameters) DeepCopyInto(out *HostnameParameters) {
	*out = *in
	if in.URLHostname != nil {
		in, out := &in.URLHostname, &out.URLHostname
		*out = new(string)
		**out = **in
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new HostnameParameters.
func (in *HostnameParameters) DeepCopy() *HostnameParameters {
	if in == nil {
		return nil
	}
	out := new(HostnameParameters)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *Item) DeepCopyInto(out *Item) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new Item.
func (in *Item) DeepCopy() *Item {
	if in == nil {
		return nil
	}
	out := new(Item)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *Item) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ItemInitParameters) DeepCopyInto(out *ItemInitParameters) {
	*out = *in
	if in.AccountID != nil {
		in, out := &in.AccountID, &out.AccountID
		*out = new(string)
		**out = **in
	}
	if in.Asn != nil {
		in, out := &in.Asn, &out.Asn
		*out = new(float64)
		**out = **in
	}
	if in.Comment != nil {
		in, out := &in.Comment, &out.Comment
		*out = new(string)
		**out = **in
	}
	if in.Hostname != nil {
		in, out := &in.Hostname, &out.Hostname
		*out = new(HostnameInitParameters)
		(*in).DeepCopyInto(*out)
	}
	if in.IP != nil {
		in, out := &in.IP, &out.IP
		*out = new(string)
		**out = **in
	}
	if in.ListID != nil {
		in, out := &in.ListID, &out.ListID
		*out = new(string)
		**out = **in
	}
	if in.Redirect != nil {
		in, out := &in.Redirect, &out.Redirect
		*out = new(RedirectInitParameters)
		(*in).DeepCopyInto(*out)
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ItemInitParameters.
func (in *ItemInitParameters) DeepCopy() *ItemInitParameters {
	if in == nil {
		return nil
	}
	out := new(ItemInitParameters)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ItemList) DeepCopyInto(out *ItemList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]Item, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ItemList.
func (in *ItemList) DeepCopy() *ItemList {
	if in == nil {
		return nil
	}
	out := new(ItemList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *ItemList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ItemObservation) DeepCopyInto(out *ItemObservation) {
	*out = *in
	if in.AccountID != nil {
		in, out := &in.AccountID, &out.AccountID
		*out = new(string)
		**out = **in
	}
	if in.Asn != nil {
		in, out := &in.Asn, &out.Asn
		*out = new(float64)
		**out = **in
	}
	if in.Comment != nil {
		in, out := &in.Comment, &out.Comment
		*out = new(string)
		**out = **in
	}
	if in.CreatedOn != nil {
		in, out := &in.CreatedOn, &out.CreatedOn
		*out = new(string)
		**out = **in
	}
	if in.Hostname != nil {
		in, out := &in.Hostname, &out.Hostname
		*out = new(HostnameObservation)
		(*in).DeepCopyInto(*out)
	}
	if in.ID != nil {
		in, out := &in.ID, &out.ID
		*out = new(string)
		**out = **in
	}
	if in.IP != nil {
		in, out := &in.IP, &out.IP
		*out = new(string)
		**out = **in
	}
	if in.ListID != nil {
		in, out := &in.ListID, &out.ListID
		*out = new(string)
		**out = **in
	}
	if in.ModifiedOn != nil {
		in, out := &in.ModifiedOn, &out.ModifiedOn
		*out = new(string)
		**out = **in
	}
	if in.OperationID != nil {
		in, out := &in.OperationID, &out.OperationID
		*out = new(string)
		**out = **in
	}
	if in.Redirect != nil {
		in, out := &in.Redirect, &out.Redirect
		*out = new(RedirectObservation)
		(*in).DeepCopyInto(*out)
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ItemObservation.
func (in *ItemObservation) DeepCopy() *ItemObservation {
	if in == nil {
		return nil
	}
	out := new(ItemObservation)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ItemParameters) DeepCopyInto(out *ItemParameters) {
	*out = *in
	if in.AccountID != nil {
		in, out := &in.AccountID, &out.AccountID
		*out = new(string)
		**out = **in
	}
	if in.Asn != nil {
		in, out := &in.Asn, &out.Asn
		*out = new(float64)
		**out = **in
	}
	if in.Comment != nil {
		in, out := &in.Comment, &out.Comment
		*out = new(string)
		**out = **in
	}
	if in.Hostname != nil {
		in, out := &in.Hostname, &out.Hostname
		*out = new(HostnameParameters)
		(*in).DeepCopyInto(*out)
	}
	if in.IP != nil {
		in, out := &in.IP, &out.IP
		*out = new(string)
		**out = **in
	}
	if in.ListID != nil {
		in, out := &in.ListID, &out.ListID
		*out = new(string)
		**out = **in
	}
	if in.Redirect != nil {
		in, out := &in.Redirect, &out.Redirect
		*out = new(RedirectParameters)
		(*in).DeepCopyInto(*out)
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ItemParameters.
func (in *ItemParameters) DeepCopy() *ItemParameters {
	if in == nil {
		return nil
	}
	out := new(ItemParameters)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ItemSpec) DeepCopyInto(out *ItemSpec) {
	*out = *in
	in.ResourceSpec.DeepCopyInto(&out.ResourceSpec)
	in.ForProvider.DeepCopyInto(&out.ForProvider)
	in.InitProvider.DeepCopyInto(&out.InitProvider)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ItemSpec.
func (in *ItemSpec) DeepCopy() *ItemSpec {
	if in == nil {
		return nil
	}
	out := new(ItemSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ItemStatus) DeepCopyInto(out *ItemStatus) {
	*out = *in
	in.ResourceStatus.DeepCopyInto(&out.ResourceStatus)
	in.AtProvider.DeepCopyInto(&out.AtProvider)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ItemStatus.
func (in *ItemStatus) DeepCopy() *ItemStatus {
	if in == nil {
		return nil
	}
	out := new(ItemStatus)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *RedirectInitParameters) DeepCopyInto(out *RedirectInitParameters) {
	*out = *in
	if in.IncludeSubdomains != nil {
		in, out := &in.IncludeSubdomains, &out.IncludeSubdomains
		*out = new(bool)
		**out = **in
	}
	if in.PreservePathSuffix != nil {
		in, out := &in.PreservePathSuffix, &out.PreservePathSuffix
		*out = new(bool)
		**out = **in
	}
	if in.PreserveQueryString != nil {
		in, out := &in.PreserveQueryString, &out.PreserveQueryString
		*out = new(bool)
		**out = **in
	}
	if in.SourceURL != nil {
		in, out := &in.SourceURL, &out.SourceURL
		*out = new(string)
		**out = **in
	}
	if in.StatusCode != nil {
		in, out := &in.StatusCode, &out.StatusCode
		*out = new(float64)
		**out = **in
	}
	if in.SubpathMatching != nil {
		in, out := &in.SubpathMatching, &out.SubpathMatching
		*out = new(bool)
		**out = **in
	}
	if in.TargetURL != nil {
		in, out := &in.TargetURL, &out.TargetURL
		*out = new(string)
		**out = **in
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new RedirectInitParameters.
func (in *RedirectInitParameters) DeepCopy() *RedirectInitParameters {
	if in == nil {
		return nil
	}
	out := new(RedirectInitParameters)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *RedirectObservation) DeepCopyInto(out *RedirectObservation) {
	*out = *in
	if in.IncludeSubdomains != nil {
		in, out := &in.IncludeSubdomains, &out.IncludeSubdomains
		*out = new(bool)
		**out = **in
	}
	if in.PreservePathSuffix != nil {
		in, out := &in.PreservePathSuffix, &out.PreservePathSuffix
		*out = new(bool)
		**out = **in
	}
	if in.PreserveQueryString != nil {
		in, out := &in.PreserveQueryString, &out.PreserveQueryString
		*out = new(bool)
		**out = **in
	}
	if in.SourceURL != nil {
		in, out := &in.SourceURL, &out.SourceURL
		*out = new(string)
		**out = **in
	}
	if in.StatusCode != nil {
		in, out := &in.StatusCode, &out.StatusCode
		*out = new(float64)
		**out = **in
	}
	if in.SubpathMatching != nil {
		in, out := &in.SubpathMatching, &out.SubpathMatching
		*out = new(bool)
		**out = **in
	}
	if in.TargetURL != nil {
		in, out := &in.TargetURL, &out.TargetURL
		*out = new(string)
		**out = **in
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new RedirectObservation.
func (in *RedirectObservation) DeepCopy() *RedirectObservation {
	if in == nil {
		return nil
	}
	out := new(RedirectObservation)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *RedirectParameters) DeepCopyInto(out *RedirectParameters) {
	*out = *in
	if in.IncludeSubdomains != nil {
		in, out := &in.IncludeSubdomains, &out.IncludeSubdomains
		*out = new(bool)
		**out = **in
	}
	if in.PreservePathSuffix != nil {
		in, out := &in.PreservePathSuffix, &out.PreservePathSuffix
		*out = new(bool)
		**out = **in
	}
	if in.PreserveQueryString != nil {
		in, out := &in.PreserveQueryString, &out.PreserveQueryString
		*out = new(bool)
		**out = **in
	}
	if in.SourceURL != nil {
		in, out := &in.SourceURL, &out.SourceURL
		*out = new(string)
		**out = **in
	}
	if in.StatusCode != nil {
		in, out := &in.StatusCode, &out.StatusCode
		*out = new(float64)
		**out = **in
	}
	if in.SubpathMatching != nil {
		in, out := &in.SubpathMatching, &out.SubpathMatching
		*out = new(bool)
		**out = **in
	}
	if in.TargetURL != nil {
		in, out := &in.TargetURL, &out.TargetURL
		*out = new(string)
		**out = **in
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new RedirectParameters.
func (in *RedirectParameters) DeepCopy() *RedirectParameters {
	if in == nil {
		return nil
	}
	out := new(RedirectParameters)
	in.DeepCopyInto(out)
	return out
}
