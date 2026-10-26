package primitives

import (
	"errors"
	"fmt"
	"slices"

	"github.com/SUNET/vc/pkg/claimpath"
)

// Shapes are how a derivation list's claims are held: the source claims
// it reads, and the document of the credential it issues, which it
// writes.
type Shapes struct {
	Source claimpath.Shape
	Issued claimpath.Shape
}

// Working is the claims a derivation list runs on: the source claims it
// reads, and the document of the credential it issues. The document
// starts as the processed source claims (claimpath.Shape.Processed) and
// takes every write. It implements Claims.
type Working struct {
	source   map[string]any
	document map[string]any
	shapes   Shapes
	written  []claimpath.Pointer
}

// NewWorking returns the working claims of a derivation list over the
// source claims.
func NewWorking(source map[string]any, shapes Shapes) *Working {
	return &Working{source: source, document: shapes.Source.Processed(source), shapes: shapes}
}

// Input implements Claims. A claim whose structure does not match the
// pointer is the data's fault, so the error is ErrInvalidClaimInput.
func (w *Working) Input(p claimpath.Pointer) (any, bool, error) {
	shape, claims := w.input(p)
	value, present, err := shape.Get(claims, p)
	if errors.Is(err, claimpath.ErrMismatch) {
		return nil, false, fmt.Errorf("%w: %w", ErrInvalidClaimInput, err)
	}
	return value, present, err
}

// Issued implements Claims.
func (w *Working) Issued(p claimpath.Pointer) (any, bool, error) {
	return w.shapes.Issued.Get(w.document, p)
}

// Document returns the document of the issued credential, with every
// write so far.
func (w *Working) Document() map[string]any {
	return w.document
}

// Pin writes a deep copy of each pinned claim, by name, into the source
// claims and into the document. A copy each time keeps pinned as it was
// whatever a later derivation writes into the claim.
func (w *Working) Pin(pinned map[string]any) {
	for name, value := range pinned {
		w.source[name] = claimpath.Clone(value)
		w.document[name] = claimpath.Clone(value)
	}
}

// Named implements Claims.
func (w *Working) Named(name string) (claimpath.Pointer, error) {
	return w.shapes.Issued.Dotted(name)
}

// InputShape returns the shape an input pointer reads: the issued shape
// when an earlier derivation writes the pointer or a prefix of it, the
// source shape otherwise.
func (w *Working) InputShape(p claimpath.Pointer) claimpath.Shape {
	shape, _ := w.input(p)
	return shape
}

// input returns the shape and the claims an input pointer reads.
func (w *Working) input(p claimpath.Pointer) (claimpath.Shape, map[string]any) {
	if writtenBefore(w.written, p) {
		return w.shapes.Issued, w.document
	}
	return w.shapes.Source, w.source
}

// Write writes value at a pointer into the document.
func (w *Working) Write(p claimpath.Pointer, value any) error {
	return w.shapes.Issued.Set(w.document, p, value)
}

// Wrote records the claims a derivation writes, for the inputs of the
// derivations after it.
func (w *Working) Wrote(outputs []claimpath.Pointer) {
	w.written = append(w.written, outputs...)
}

// writtenBefore reports whether one of written is p or a prefix of it.
func writtenBefore(written []claimpath.Pointer, p claimpath.Pointer) bool {
	return slices.ContainsFunc(written, func(q claimpath.Pointer) bool { return p.HasPrefix(q) })
}

// ResolveDerivations reads the dotted claims of a derivation list, and
// checks that every claim the list reads or writes is one claim its shape
// locates.
//
//   - An output, and an unset output of a primitive that writes in place,
//     is a claim of the issued credential's document.
//   - An input is a claim of the source data. An input whose dotted name is
//     an earlier derivation's output, or one beneath it, is a claim of the
//     issued document: the derivations chain.
//   - An hkdf input is a claim of the source data.
//   - An unset output with an input that reads presented claims by index
//     is refused: the document holds the processed claims, where that
//     element can sit at another index (claimpath.Shape.Renumbers).
func ResolveDerivations(list []Derivation, shapes Shapes) error {
	var written []claimpath.Pointer
	for i := range list {
		a, name, err := list[i].selected()
		if err != nil {
			return fmt.Errorf("derivations[%d]: %w", i, err)
		}
		if err := resolveArgs(a, shapes, written); err != nil {
			return fmt.Errorf("derivations[%d].%s.%w", i, name, err)
		}
		outputs, err := list[i].Outputs(shapes.Issued.Dotted)
		if err != nil {
			return fmt.Errorf("derivations[%d].%s: %w", i, name, err)
		}
		written = append(written, outputs...)
	}
	return nil
}

// resolveArgs resolves the claims of one primitive's arguments.
func resolveArgs(a Applier, shapes Shapes, written []claimpath.Pointer) error {
	if hc, ok := a.(*HashCommitmentArgs); ok {
		return hc.resolve(shapes.Source)
	}
	input, hasInput := pointerField(a, "Input")
	output, hasOutput := pointerField(a, "Output")
	inPlace := hasInput && hasOutput && output.IsZero()
	if hasOutput {
		if err := resolveOutput(output, input, shapes.Issued); err != nil {
			return fmt.Errorf("output: %w", err)
		}
	}
	if !hasInput {
		return nil
	}
	if err := resolveInput(input, shapes, written); err != nil {
		return fmt.Errorf("input: %w", err)
	}
	if inPlace && !writtenBefore(written, *input) && shapes.Source.Renumbers(*input) {
		return fmt.Errorf("output: the input %s reads the presented claims by index, and the issued document can hold that element at another index; set output", *input)
	}
	return nil
}

// resolveOutput resolves an output in the issued claims. An unset output
// is the input, written in place: a dotted input names it by the same
// dotted name.
func resolveOutput(output, input *claimpath.Pointer, issued claimpath.Shape) error {
	if input != nil && output.IsZero() {
		*output = *input
	}
	return issued.ResolveOne(output)
}

// resolveInput resolves an input in the source claims, or in the issued
// claims when its dotted name is an earlier output or beneath one.
func resolveInput(input *claimpath.Pointer, shapes Shapes, written []claimpath.Pointer) error {
	chained := func(dotted string) (claimpath.Pointer, error) {
		if issued, err := shapes.Issued.Dotted(dotted); err == nil && writtenBefore(written, issued) {
			return issued, nil
		}
		return shapes.Source.Dotted(dotted)
	}
	if err := input.Resolve(chained); err != nil {
		return err
	}
	space := shapes.Source
	if writtenBefore(written, *input) {
		space = shapes.Issued
	}
	return space.ResolveOne(input)
}
