package claimpath

import (
	"errors"
	"fmt"
	"reflect"
)

// ErrNoClaim is the error of a pointer that selects nothing.
var ErrNoClaim = errors.New("claimpath: the pointer selects no claim")

// ErrMismatch is the error of a pointer whose component meets a value of
// the wrong type: a key on a non-object, or null or an index on a
// non-array.
var ErrMismatch = errors.New("claimpath: the claims do not have the structure the pointer selects")

// Select processes the pointer against a JSON credential as OpenID4VP 1.0
// section 7.1 defines it, starting at the root object. A missing key or
// index drops its element from the selection. A key on a non-object and
// null or an index on a non-array are an error, and so is an empty final
// selection.
func (p Pointer) Select(root map[string]any) ([]any, error) {
	return p.selectIn(root, false)
}

// selectIn is Select, which skips the undisclosed array elements of
// presented claims when positional is set.
func (p Pointer) selectIn(root map[string]any, positional bool) ([]any, error) {
	components, err := p.Components()
	if err != nil {
		return nil, err
	}
	selection := []any{root}
	for i, c := range components {
		next := make([]any, 0, len(selection))
		for _, element := range selection {
			children, err := c.children(element, positional)
			if err != nil {
				return nil, fmt.Errorf("%w: %s, element %d: %w", ErrMismatch, p, i, err)
			}
			next = append(next, children...)
		}
		selection = next
	}
	if len(selection) == 0 {
		return nil, fmt.Errorf("%w: %s", ErrNoClaim, p)
	}
	return selection, nil
}

// children returns what the component selects in one element. When
// positional is set, an array keeps the elements the holder did not
// disclose at their positions, and null and an index select none of them.
func (c Component) children(element any, positional bool) ([]any, error) {
	if c.kind == keyKind {
		object, ok := element.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("key %q on a %T", c.key, element)
		}
		if value, present := object[c.key]; present {
			return []any{value}, nil
		}
		return nil, nil
	}
	array, ok := asArray(element)
	if !ok {
		return nil, fmt.Errorf("%s on a %T", c, element)
	}
	if c.kind == allKind {
		return disclosedElements(array, positional), nil
	}
	if c.index < uint(len(array)) {
		return disclosedElements(array[c.index:c.index+1], positional), nil
	}
	return nil, nil
}

// disclosedElements returns the elements, without the undisclosed ones
// when positional is set.
func disclosedElements(elements []any, positional bool) []any {
	if !positional {
		return elements
	}
	out := make([]any, 0, len(elements))
	for _, element := range elements {
		if !undisclosed(element) {
			out = append(out, element)
		}
	}
	return out
}

// String renders the component as its JSON value.
func (c Component) String() string {
	return New(c).String()
}

// asArray returns the elements of a JSON array, whichever slice type
// holds it.
func asArray(value any) ([]any, bool) {
	if v, ok := value.([]any); ok {
		return v, true
	}
	rv, ok := arrayValue(value)
	if !ok {
		return nil, false
	}
	out := make([]any, rv.Len())
	for i := range out {
		out[i] = rv.Index(i).Interface()
	}
	return out, true
}

// arrayValue returns the slice that holds a JSON array. A byte slice is a
// byte string.
func arrayValue(value any) (reflect.Value, bool) {
	if _, bytes := value.([]byte); bytes || value == nil {
		return reflect.Value{}, false
	}
	rv := reflect.ValueOf(value)
	return rv, rv.Kind() == reflect.Slice
}

// get returns the one claim a pointer of keys and indices selects, with
// the undisclosed array elements of presented claims when positional is
// set (see children).
func (p Pointer) get(root map[string]any, positional bool) (any, bool, error) {
	var current any = root
	for i, c := range p.components {
		children, err := c.children(current, positional)
		if err != nil {
			return nil, false, fmt.Errorf("%w: %s, element %d: %w", ErrMismatch, p, i, err)
		}
		if len(children) == 0 {
			return nil, false, nil
		}
		current = children[0]
	}
	return current, true, nil
}

// set writes value at a pointer of keys and indices. It creates the
// objects a missing key passes through, and never an array or an array
// element: an index writes into an element that is there.
func (p Pointer) set(root map[string]any, value any) error {
	n := len(p.components) - 1
	var container any = root
	for i, c := range p.components[:n] {
		next, err := c.child(container, p.components[i+1])
		if err != nil {
			return fmt.Errorf("%w: %s, element %d: %w", ErrMismatch, p, i, err)
		}
		container = next
	}
	if err := p.components[n].put(container, value); err != nil {
		return fmt.Errorf("%w: %s, element %d: %w", ErrMismatch, p, n, err)
	}
	return nil
}

// child returns the container the component selects in container, and
// creates an object at a missing key that the next component, a key,
// passes through.
func (c Component) child(container any, next Component) (any, error) {
	children, err := c.children(container, false)
	if err != nil {
		return nil, err
	}
	if len(children) == 1 {
		return children[0], nil
	}
	if c.kind != keyKind || next.kind != keyKind {
		return nil, fmt.Errorf("%s selects no element to write into", c)
	}
	created := map[string]any{}
	container.(map[string]any)[c.key] = created
	return created, nil
}

// put writes value at the component in container.
func (c Component) put(container any, value any) error {
	switch c.kind {
	case keyKind:
		object, ok := container.(map[string]any)
		if !ok {
			return fmt.Errorf("key %q on a %T", c.key, container)
		}
		object[c.key] = value
		return nil
	case indexKind:
		return c.putElement(container, value)
	}
	return fmt.Errorf("%s writes no single element", c)
}

// putElement writes value into the element an index selects, in an array
// of any slice type.
func (c Component) putElement(container any, value any) error {
	array, ok := arrayValue(container)
	if !ok {
		return fmt.Errorf("%s on a %T", c, container)
	}
	if c.index >= uint(array.Len()) {
		return fmt.Errorf("%s on an array of %d elements", c, array.Len())
	}
	element := array.Index(int(c.index))
	written := reflect.ValueOf(value)
	if !written.IsValid() {
		written = reflect.Zero(element.Type())
	}
	if !written.Type().AssignableTo(element.Type()) || (value == nil && !nillable(element.Kind())) {
		return fmt.Errorf("%s: a %T is no element of a %T", c, value, container)
	}
	element.Set(written)
	return nil
}

// nillable reports whether a value of kind k can be nil.
func nillable(k reflect.Kind) bool {
	switch k {
	case reflect.Interface, reflect.Pointer, reflect.Map, reflect.Slice:
		return true
	}
	return false
}
