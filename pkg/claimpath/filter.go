package claimpath

import (
	"errors"
	"fmt"
)

// ErrUndeclaredElement is the error of a document whose array has an
// element the tree does not declare before one it does: dropping the
// first would move the second to another index.
var ErrUndeclaredElement = errors.New("claimpath: an undeclared array element precedes a declared one")

// Filter returns the claims of doc the tree declares, and nothing else.
//
// A declared claim keeps its whole value. An object keeps the declared
// keys it holds. An array keeps every element at its position: an index
// points at that position in the filtered document as in doc (OpenID4VP
// 1.0 section 7.1). A declared element nothing declared survives in is
// kept as its empty container when a later element survives, and dropped
// at the end of the array. An undeclared element before one that survives
// is an ErrUndeclaredElement error.
//
// A value whose type the tree contradicts, such as a string where the tree
// declares keys, is an ErrMismatch error, as Select reports it.
func (t *Tree) Filter(doc map[string]any) (map[string]any, error) {
	filtered, _, err := filterObject(doc, t.root, Pointer{})
	return filtered, err
}

// filterValue returns what n declares in value, and whether a declared
// claim survives in it.
func filterValue(value any, n *node, at Pointer) (any, bool, error) {
	if n.declared {
		return value, true, nil
	}
	if n.keys != nil {
		object, ok := value.(map[string]any)
		if !ok {
			return nil, false, fmt.Errorf("%w: %s is a %T where the declared claims below it need an object", ErrMismatch, at, value)
		}
		return filterObject(object, n, at)
	}
	elements, ok := asArray(value)
	if !ok {
		return nil, false, fmt.Errorf("%w: %s is a %T where the declared claims below it need an array", ErrMismatch, at, value)
	}
	return filterArray(elements, n, at)
}

// filterObject returns the declared keys of object that survive.
func filterObject(object map[string]any, n *node, at Pointer) (map[string]any, bool, error) {
	out := make(map[string]any, len(n.keys))
	for key, child := range n.keys {
		value, present := object[key]
		if !present {
			continue
		}
		filtered, survives, err := filterValue(value, child, at.Append(Key(key)))
		if err != nil {
			return nil, false, err
		}
		if survives {
			out[key] = filtered
		}
	}
	return out, len(out) > 0, nil
}

// filterArray returns the elements of an array up to the last one in
// which a declared claim survives, each at its position.
func filterArray(elements []any, n *node, at Pointer) ([]any, bool, error) {
	out := make([]any, len(elements))
	last := -1
	for i, element := range elements {
		declared := n.element(uint(i))
		if declared == nil {
			continue
		}
		filtered, survives, err := filterValue(element, declared, at.Append(Index(uint(i))))
		if err != nil {
			return nil, false, err
		}
		out[i] = filtered
		if survives {
			last = i
		}
	}
	for i := range last {
		if n.element(uint(i)) == nil {
			return nil, false, fmt.Errorf("%w: %s, element %d before element %d", ErrUndeclaredElement, at, i, last)
		}
	}
	return out[:last+1], last >= 0, nil
}

// Template returns a document with the tree's structure and leaf at every
// declared claim. An array holds one element for null, and an element at
// each declared index, with leaf at a position below it the tree does not
// declare.
func (t *Tree) Template(leaf any) map[string]any {
	return templateObject(t.root, leaf)
}

func templateOf(n *node, leaf any) any {
	switch {
	case n.keys != nil:
		return templateObject(n, leaf)
	case n.all != nil || n.indices != nil:
		return templateArray(n, leaf)
	}
	return leaf
}

func templateObject(n *node, leaf any) map[string]any {
	out := make(map[string]any, len(n.keys))
	for key, child := range n.keys {
		out[key] = templateOf(child, leaf)
	}
	return out
}

func templateArray(n *node, leaf any) []any {
	out := make([]any, n.length())
	for i := range out {
		out[i] = leaf
		if child := n.element(uint(i)); child != nil {
			out[i] = templateOf(child, leaf)
		}
	}
	return out
}
