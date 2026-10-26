package claimpath

import "reflect"

// Clone returns a deep copy of a claim value: its objects and its arrays,
// of any slice type, share nothing with v, so a write into the copy leaves
// v as it was. A nil object copies to an empty one.
func Clone[V any](v V) V {
	return typed[V](copyValue(any(v), false))
}

// typed returns v as a V.
func typed[V any](v any) V {
	out, ok := v.(V)
	if !ok {
		var zero V
		return zero
	}
	return out
}

// copyValue deep-copies v, without the array elements the holder did not
// disclose when withheld is set.
func copyValue(v any, withheld bool) any {
	switch typed := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(typed))
		for key, item := range typed {
			out[key] = copyValue(item, withheld)
		}
		return out
	case []any:
		out := make([]any, 0, len(typed))
		for _, item := range typed {
			if withheld && undisclosed(item) {
				continue
			}
			out = append(out, copyValue(item, withheld))
		}
		return out
	}
	return copySlice(v)
}

// undisclosed reports whether an array element is one the holder did not
// disclose: the {"...": digest} object an SD-JWT holds in its place (RFC
// 9901 section 4.2.4.2). The claim name "..." is reserved, so no disclosed
// value has that form.
func undisclosed(v any) bool {
	object, ok := v.(map[string]any)
	if !ok || len(object) != 1 {
		return false
	}
	_, ok = object["..."].(string)
	return ok
}

// copySlice deep-copies a slice of another element type, such as the
// []string an attribute mapping writes. Any other value is immutable and
// returned as it is.
func copySlice(v any) any {
	slice := reflect.ValueOf(v)
	if slice.Kind() != reflect.Slice || slice.IsNil() {
		return v
	}
	out := reflect.MakeSlice(slice.Type(), slice.Len(), slice.Len())
	for i := range slice.Len() {
		if item := copyValue(slice.Index(i).Interface(), false); item != nil {
			out.Index(i).Set(reflect.ValueOf(item))
		}
	}
	return out.Interface()
}
