package claimpath

import "reflect"

// Clone returns a deep copy of a claim value: its objects and its arrays,
// of any slice type, share nothing with v, so a write into the copy leaves
// v as it was. A nil object copies to an empty one.
func Clone[V any](v V) V {
	copied, ok := copyValue(any(v)).(V)
	if !ok {
		var zero V
		return zero
	}
	return copied
}

func copyValue(v any) any {
	switch typed := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(typed))
		for key, item := range typed {
			out[key] = copyValue(item)
		}
		return out
	case []any:
		out := make([]any, len(typed))
		for i, item := range typed {
			out[i] = copyValue(item)
		}
		return out
	}
	return copySlice(v)
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
		if item := copyValue(slice.Index(i).Interface()); item != nil {
			out.Index(i).Set(reflect.ValueOf(item))
		}
	}
	return out.Interface()
}
