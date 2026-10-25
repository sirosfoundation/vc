package claimpath

import (
	"errors"
	"fmt"
	"maps"
	"slices"
)

// ErrConflict is the error of a set of pointers that OpenID4VCI 1.0
// Appendix B.3 refuses: two pointers address the same claim, one addresses
// every element of an array and another one element of it, or one treats a
// claim as an array and another as an object.
var ErrConflict = errors.New("claimpath: the claims path pointers contradict each other")

// Tree is the structure a set of pointers declares, such as the claims of
// a type metadata document. Every pointer starts with a key, since it
// points into a credential's JSON object, and no two pointers conflict
// (see ErrConflict).
type Tree struct {
	root *node
}

// node is a claim of a Tree. A node with keys is an object, a node with
// all or indices is an array, and B.3 keeps a node from being both.
type node struct {
	// declared marks the claim a pointer ends at.
	declared bool
	// by is the first pointer through the node, for an error naming the
	// pointer another one conflicts with.
	by      Pointer
	keys    map[string]*node
	all     *node
	indices map[uint]*node
}

// NewTree returns the tree of pointers.
func NewTree(pointers []Pointer) (*Tree, error) {
	root := &node{keys: map[string]*node{}}
	for _, p := range pointers {
		components, err := p.Components()
		if err != nil {
			return nil, err
		}
		if _, ok := components[0].KeyName(); !ok {
			return nil, fmt.Errorf("%w: %s starts with %s, and a credential is a JSON object", ErrConflict, p, components[0])
		}
		if err := root.insert(p, components); err != nil {
			return nil, err
		}
	}
	return &Tree{root: root}, nil
}

// insert adds the claims of p along components below n.
func (n *node) insert(p Pointer, components []Component) error {
	current := n
	for _, c := range components {
		next, err := current.child(p, c)
		if err != nil {
			return err
		}
		current = next
	}
	if current.declared {
		return fmt.Errorf("%w: %s is addressed twice", ErrConflict, p)
	}
	current.declared = true
	return nil
}

// child returns the node c selects below n, adding it for p.
func (n *node) child(p Pointer, c Component) (*node, error) {
	if err := n.accepts(c); err != nil {
		return nil, fmt.Errorf("%w: %s and %s: %w", ErrConflict, n.by, p, err)
	}
	if n.by.IsZero() {
		n.by = p
	}
	switch c.kind {
	case keyKind:
		return descend(&n.keys, c.key), nil
	case allKind:
		if n.all == nil {
			n.all = &node{}
		}
		return n.all, nil
	}
	return descend(&n.indices, c.index), nil
}

// descend returns the node at key in *children, adding it.
func descend[K comparable](children *map[K]*node, key K) *node {
	if *children == nil {
		*children = map[K]*node{}
	}
	child, ok := (*children)[key]
	if !ok {
		child = &node{}
		(*children)[key] = child
	}
	return child
}

// accepts refuses a component that B.3 forbids beside n's children.
func (n *node) accepts(c Component) error {
	array := n.all != nil || n.indices != nil
	switch {
	case c.kind == keyKind && array, c.kind != keyKind && n.keys != nil:
		return errors.New("one is an array and the other an object")
	case c.kind == allKind && n.indices != nil, c.kind == indexKind && n.all != nil:
		return errors.New("one selects every element of an array and the other one element")
	}
	return nil
}

// element returns the node of element i of an array node.
func (n *node) element(i uint) *node {
	if n.all != nil {
		return n.all
	}
	return n.indices[i]
}

// length returns the number of elements an array node declares: one for
// null, and up to the highest index otherwise.
func (n *node) length() int {
	if n.all != nil {
		return 1
	}
	return int(slices.Max(slices.Collect(maps.Keys(n.indices)))) + 1
}
