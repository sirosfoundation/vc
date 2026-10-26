package claimpath

import (
	"errors"
	"fmt"
	"slices"
	"strings"
)

// Shape is how a claims map holds the claims of a credential. A pointer
// names a claim of the credential; the shape locates that claim in the
// map.
//
//   - Nested holds a JSON-based credential (SD-JWT VC, W3C) as its JSON
//     object.
//   - Presented holds the claims of a presented JSON-based credential,
//     with each array element the holder did not disclose at its
//     position.
//   - MDocQualified holds a presented ISO mdoc: one flat key
//     "<namespace>.<element>" per data element.
//   - MDocElements holds the document data of an ISO mdoc: one key per
//     data element identifier, in a namespace the MDDL declares.
type Shape struct {
	kind shapeKind
	// defaultNamespace is the namespace of a dotted name without a dot,
	// for MDocQualified.
	defaultNamespace string
	// namespaces maps an element identifier to the namespaces that
	// declare it, for MDocElements.
	namespaces map[string][]string
}

type shapeKind uint8

const (
	nestedShape shapeKind = iota + 1
	presentedShape
	mdocQualifiedShape
	mdocElementsShape
)

// Nested returns the shape of a JSON-based credential.
func Nested() Shape { return Shape{kind: nestedShape} }

// Presented returns the shape of the claims of a presented JSON-based
// credential (SD-JWT VC, W3C). An SD-JWT's claims keep each array element
// the holder did not disclose at its position, as the {"...": digest} the
// SD-JWT holds there, since an index counts the elements of the array as
// issued (SD-JWT VC section 5.6). An index on such an element selects
// nothing, and null skips it. A value a read returns holds none of them.
func Presented() Shape { return Shape{kind: presentedShape} }

// MDocQualified returns the shape of a presented mdoc. A dotted name
// without a dot is an element of defaultNamespace.
func MDocQualified(defaultNamespace string) Shape {
	return Shape{kind: mdocQualifiedShape, defaultNamespace: defaultNamespace}
}

// MDocElements returns the shape of mdoc document data whose MDDL
// declares the elements of declared, by namespace.
func MDocElements[M ~map[string]V, V any](declared map[string]M) Shape {
	namespaces := map[string][]string{}
	for namespace, elements := range declared {
		for element := range elements {
			namespaces[element] = append(namespaces[element], namespace)
		}
	}
	for _, list := range namespaces {
		slices.Sort(list)
	}
	return Shape{kind: mdocElementsShape, namespaces: namespaces}
}

// Locate returns where the claim p names sits in a claims map of the
// shape, as a pointer through its objects and arrays.
//
// An MDocElements pointer is [namespace, element] for an element the MDDL
// declares in that namespace. A single-key pointer [key] addresses a
// document key the MDDL does not declare: an intermediate claim a
// derivation reads or writes. It exists so configuration written as
// dotted names keeps working.
func (s Shape) Locate(p Pointer) (Pointer, error) {
	if _, err := p.Components(); err != nil {
		return Pointer{}, err
	}
	switch s.kind {
	case nestedShape, presentedShape:
		return p, nil
	case mdocQualifiedShape:
		namespace, element, err := p.MDoc()
		if err != nil {
			return Pointer{}, err
		}
		return Keys(namespace + "." + element), nil
	case mdocElementsShape:
		return s.locateElement(p)
	}
	return Pointer{}, errors.New("claimpath: the shape is unset")
}

func (s Shape) locateElement(p Pointer) (Pointer, error) {
	keys, ok := p.KeyNames()
	switch {
	case ok && len(keys) == 2:
		if !slices.Contains(s.namespaces[keys[1]], keys[0]) {
			return Pointer{}, fmt.Errorf("claimpath: the MDDL declares no element %q in namespace %q", keys[1], keys[0])
		}
		return Keys(keys[1]), nil
	case ok && len(keys) == 1:
		if declaring := s.namespaces[keys[0]]; len(declaring) > 0 {
			return Pointer{}, fmt.Errorf("claimpath: the MDDL declares %q in %s; name it [namespace, element]", keys[0], strings.Join(declaring, " and "))
		}
		return p, nil
	}
	return Pointer{}, fmt.Errorf("claimpath: %s is no [namespace, element] pointer into mdoc document data", p)
}

// LocateOne is Locate for a pointer that names one claim: it refuses a
// pointer with null.
func (s Shape) LocateOne(p Pointer) (Pointer, error) {
	location, err := s.Locate(p)
	if err != nil {
		return Pointer{}, err
	}
	if !p.SelectsOne() {
		return Pointer{}, fmt.Errorf("claimpath: %s selects every element of an array where one claim is named", p)
	}
	return location, nil
}

// ResolveOne reads a pending pointer as a dotted name of the shape, and
// checks that a set pointer names one claim the shape locates.
func (s Shape) ResolveOne(p *Pointer) error {
	if err := p.Resolve(s.Dotted); err != nil {
		return err
	}
	if p.IsZero() {
		return nil
	}
	_, err := s.LocateOne(*p)
	return err
}

// Dotted reads a dotted claim name as a pointer into the shape.
//
//   - Nested and Presented split it on dots, one key per segment.
//   - MDocQualified splits it at the last dot into [namespace, element],
//     and reads a name without an inner dot as an element of the default
//     namespace.
//   - MDocElements reads it as an element identifier: [namespace, element]
//     for an element the MDDL declares in one namespace, [name] for a
//     name it does not declare.
func (s Shape) Dotted(name string) (Pointer, error) {
	if name == "" {
		return Pointer{}, errors.New("claimpath: a dotted claim name is non-empty")
	}
	switch s.kind {
	case nestedShape, presentedShape:
		keys := strings.Split(name, ".")
		if slices.Contains(keys, "") {
			return Pointer{}, fmt.Errorf("claimpath: %q has an empty segment", name)
		}
		return FromKeys(keys)
	case mdocQualifiedShape:
		if i := strings.LastIndex(name, "."); i > 0 && i < len(name)-1 {
			return Keys(name[:i], name[i+1:]), nil
		}
		return Keys(s.defaultNamespace, name), nil
	case mdocElementsShape:
		switch declaring := s.namespaces[name]; len(declaring) {
		case 0:
			return Keys(name), nil
		case 1:
			return Keys(declaring[0], name), nil
		default:
			return Pointer{}, fmt.Errorf("claimpath: the MDDL declares %q in %s; name it [namespace, element]", name, strings.Join(declaring, " and "))
		}
	}
	return Pointer{}, errors.New("claimpath: the shape is unset")
}

// Get returns the one claim p names in claims.
func (s Shape) Get(claims map[string]any, p Pointer) (any, bool, error) {
	location, err := s.LocateOne(p)
	if err != nil {
		return nil, false, err
	}
	value, present, err := location.get(claims, s.positional())
	if err != nil || !present || !s.positional() {
		return value, present, err
	}
	return copyValue(value, true), true, nil
}

// Set writes value at the claim p names in claims.
func (s Shape) Set(claims map[string]any, p Pointer, value any) error {
	location, err := s.LocateOne(p)
	if err != nil {
		return err
	}
	return location.set(claims, value)
}

// Select returns every claim p selects in claims (see Pointer.Select).
func (s Shape) Select(claims map[string]any, p Pointer) ([]any, error) {
	location, err := s.Locate(p)
	if err != nil {
		return nil, err
	}
	values, err := location.selectIn(claims, s.positional())
	if err != nil || !s.positional() {
		return values, err
	}
	for i, value := range values {
		values[i] = copyValue(value, true)
	}
	return values, nil
}

// Copy writes a deep copy of the claim p names in src at the same claim in
// dst, and reports whether src holds it. The copy keeps the undisclosed
// array elements of presented claims at their positions, so an index
// reads dst as it reads src.
func (s Shape) Copy(dst, src map[string]any, p Pointer) (bool, error) {
	location, err := s.LocateOne(p)
	if err != nil {
		return false, err
	}
	value, present, err := location.get(src, s.positional())
	if err != nil || !present {
		return false, err
	}
	return true, location.set(dst, Clone(value))
}

// Processed returns a deep copy of claims held in the shape, as a
// document holds them. For Presented, it is the processed payload of RFC
// 9901 section 7.1: the array elements the holder did not disclose are
// removed. Every consumer that hands presented claims on as a whole takes
// them through Processed.
func (s Shape) Processed(claims map[string]any) map[string]any {
	return typed[map[string]any](copyValue(claims, s.positional()))
}

// Renumbers reports whether Processed can move the claim p names to
// another index: p has an index, and the shape is Presented.
func (s Shape) Renumbers(p Pointer) bool {
	return s.positional() && slices.ContainsFunc(p.components, func(c Component) bool { return c.kind == indexKind })
}

// positional reports whether the claims of the shape keep undisclosed
// array elements at their positions.
func (s Shape) positional() bool { return s.kind == presentedShape }
