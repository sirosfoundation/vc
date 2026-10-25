package claimpath

import (
	"encoding/json"
	"errors"
	"reflect"
	"testing"
)

// arthurDent is the credential of the examples in OpenID4VP 1.0 section
// 7.3.
const arthurDent = `{
  "name": "Arthur Dent",
  "address": {
    "street_address": "42 Market Street",
    "locality": "Milliways",
    "postal_code": "12345"
  },
  "degrees": [
    {"type": "Bachelor of Science", "university": "University of Betelgeuse"},
    {"type": "Master of Science", "university": "University of Betelgeuse"}
  ],
  "nationalities": ["British", "Betelgeusian"]
}`

// TestSelect reproduces the examples of OpenID4VP 1.0 section 7.3, and
// each error rule of the processing in section 7.1.
func TestSelect(t *testing.T) {
	var credential map[string]any
	if err := json.Unmarshal([]byte(arthurDent), &credential); err != nil {
		t.Fatal(err)
	}
	address := map[string]any{"street_address": "42 Market Street", "locality": "Milliways", "postal_code": "12345"}

	tests := []struct {
		pointer string
		want    []any
		err     error
	}{
		{`["name"]`, []any{"Arthur Dent"}, nil},
		{`["address"]`, []any{address}, nil},
		{`["address","street_address"]`, []any{"42 Market Street"}, nil},
		{`["degrees",null,"type"]`, []any{"Bachelor of Science", "Master of Science"}, nil},
		{`["nationalities",1]`, []any{"Betelgeusian"}, nil},

		{`["name","first"]`, nil, ErrMismatch},
		{`["address",null]`, nil, ErrMismatch},
		{`["address",0]`, nil, ErrMismatch},
		{`["middle_name"]`, nil, ErrNoClaim},
		{`["nationalities",2]`, nil, ErrNoClaim},
	}
	for _, tt := range tests {
		t.Run(tt.pointer, func(t *testing.T) {
			got, err := mustPointer(t, tt.pointer).Select(credential)
			if !errors.Is(err, tt.err) {
				t.Fatalf("Select() error = %v, want %v", err, tt.err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Select() = %v, want %v", got, tt.want)
			}
		})
	}
}

func mustPointer(t *testing.T, text string) Pointer {
	t.Helper()
	var p Pointer
	if err := json.Unmarshal([]byte(text), &p); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestShapes covers where each shape locates a claim, and each rule it
// refuses a pointer by.
func TestShapes(t *testing.T) {
	elements := MDocElements(map[string]map[string]bool{
		"org.iso.18013.5.1":       {"birth_date": true, "family_name": true},
		"eu.europa.ec.eudi.pid.1": {"family_name": true},
	})
	tests := []struct {
		name   string
		shape  Shape
		claims map[string]any
		path   Pointer
		want   any
		err    bool
	}{
		{"nested object", Nested(), map[string]any{"identity": map[string]any{"birthdate": "1990"}}, Keys("identity", "birthdate"), "1990", false},
		{"nested refuses a flat dotted key", Nested(), map[string]any{"identity.birthdate": "1990"}, Keys("identity", "birthdate"), nil, false},
		{"presented mdoc element", MDocQualified("org.iso.18013.5.1"), map[string]any{"eu.europa.ec.eudi.pid.1.birth_date": "1990"}, Keys("eu.europa.ec.eudi.pid.1", "birth_date"), "1990", false},
		{"presented mdoc refuses one key", MDocQualified("org.iso.18013.5.1"), map[string]any{"birth_date": "1990"}, Keys("birth_date"), nil, true},
		{"mdoc document element", elements, map[string]any{"birth_date": "1990"}, Keys("org.iso.18013.5.1", "birth_date"), "1990", false},
		{"mdoc document refuses an undeclared namespace", elements, map[string]any{"birth_date": "1990"}, Keys("eu.europa.ec.eudi.pid.1", "birth_date"), nil, true},
		{"mdoc document refuses a declared element as one key", elements, map[string]any{"birth_date": "1990"}, Keys("birth_date"), nil, true},
		{"mdoc document key the MDDL does not declare", elements, map[string]any{"raw": "1990"}, Keys("raw"), "1990", false},
		{"mdoc document refuses three keys", elements, map[string]any{}, Keys("a", "b", "c"), nil, true},
		{"one claim refuses null", Nested(), map[string]any{"a": []any{"x"}}, New(Key("a"), All()), nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _, err := tt.shape.Get(tt.claims, tt.path)
			if (err != nil) != tt.err {
				t.Fatalf("Get() error = %v, want error %v", err, tt.err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Get() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestCheckResolved finds a pending pointer through maps, slices,
// pointers and a field a custom unmarshaler sets, and names where it is.
func TestCheckResolved(t *testing.T) {
	type leaf struct {
		Path Pointer `yaml:"-"`
	}
	type entry struct {
		Leaves []*leaf `yaml:"leaves"`
	}
	type root struct {
		Entries map[string]entry `yaml:"entries"`
	}
	pending, err := Dotted("given_name")
	if err != nil {
		t.Fatal(err)
	}
	cfg := root{Entries: map[string]entry{"pid": {Leaves: []*leaf{{Path: Keys("a")}, {Path: pending}}}}}

	var found *PendingError
	if !errors.As(CheckResolved(cfg), &found) || found.At != "entries.pid.leaves[1].path" {
		t.Fatalf("CheckResolved() = %v, want the pending pointer at entries.pid.leaves[1].path", found)
	}
	cfg.Entries["pid"].Leaves[1].Path = Keys("b")
	if err := CheckResolved(cfg); err != nil {
		t.Fatalf("CheckResolved() = %v on resolved pointers", err)
	}
}

// TestNewTreeRefusals has one fixture per contradiction OpenID4VCI 1.0
// Appendix B.3 names, the pointer into a JSON object that starts with no
// key, and an unset pointer.
func TestNewTreeRefusals(t *testing.T) {
	tests := []struct {
		name     string
		pointers []string
	}{
		{"a claim addressed twice", []string{`["a","b"]`, `["a","b"]`}},
		{"null and an index into one array", []string{`["a",null]`, `["a",0,"b"]`}},
		{"an array and an object", []string{`["a",0]`, `["a","b"]`}},
		{"an object and an array", []string{`["a","b"]`, `["a",null]`}},
		{"a pointer that starts with null", []string{`[null,"a"]`}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pointers := make([]Pointer, len(tt.pointers))
			for i, text := range tt.pointers {
				pointers[i] = mustPointer(t, text)
			}
			if _, err := NewTree(pointers); !errors.Is(err, ErrConflict) {
				t.Fatalf("NewTree() error = %v, want %v", err, ErrConflict)
			}
		})
	}
	if _, err := NewTree([]Pointer{{}}); err == nil {
		t.Fatal("NewTree() accepted an unset pointer")
	}
}

// TestTreeFilter checks the filter against documents whose filtered form
// follows by hand from the rule that an index points at the same element
// before and after filtering.
func TestTreeFilter(t *testing.T) {
	tests := []struct {
		name     string
		pointers []string
		doc      string
		want     string
	}{
		{"an object keeps its declared keys", []string{`["address","locality"]`}, `{"address":{"locality":"Milliways","street":"42 Market Street"},"name":"Arthur Dent"}`, `{"address":{"locality":"Milliways"}}`},
		{"a declared claim keeps its whole value", []string{`["nationalities"]`, `["nationalities",1]`}, `{"nationalities":["British","Betelgeusian"]}`, `{"nationalities":["British","Betelgeusian"]}`},
		{"an index keeps its position", []string{`["nationalities",0]`}, `{"nationalities":["British","Betelgeusian"]}`, `{"nationalities":["British"]}`},
		{"null keeps every position", []string{`["degrees",null,"type"]`}, `{"degrees":[{"university":"Betelgeuse"},{"type":"Master","university":"Betelgeuse"}]}`, `{"degrees":[{},{"type":"Master"}]}`},
		{"an element nothing survives in ends the array", []string{`["degrees",null,"type"]`}, `{"degrees":[{"type":"Bachelor"},{"university":"Betelgeuse"}]}`, `{"degrees":[{"type":"Bachelor"}]}`},
		{"an array nothing survives in is dropped", []string{`["degrees",null,"type"]`}, `{"degrees":[{"university":"Betelgeuse"}]}`, `{}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := mustTree(t, tt.pointers).Filter(mustObject(t, tt.doc))
			if err != nil {
				t.Fatal(err)
			}
			if want := mustObject(t, tt.want); !reflect.DeepEqual(got, want) {
				t.Errorf("Filter() = %v, want %v", got, want)
			}
		})
	}

	refusals := []struct {
		name     string
		pointers []string
		doc      string
		err      error
	}{
		{"an undeclared element before a declared one", []string{`["nationalities",1]`}, `{"nationalities":["British","Betelgeusian"]}`, ErrUndeclaredElement},
		{"a string where keys are declared", []string{`["address","locality"]`}, `{"address":"42 Market Street"}`, ErrMismatch},
	}
	for _, tt := range refusals {
		t.Run(tt.name, func(t *testing.T) {
			_, err := mustTree(t, tt.pointers).Filter(mustObject(t, tt.doc))
			if !errors.Is(err, tt.err) {
				t.Fatalf("Filter() error = %v, want %v", err, tt.err)
			}
		})
	}
}

func mustTree(t *testing.T, pointers []string) *Tree {
	t.Helper()
	parsed := make([]Pointer, len(pointers))
	for i, text := range pointers {
		parsed[i] = mustPointer(t, text)
	}
	tree, err := NewTree(parsed)
	if err != nil {
		t.Fatal(err)
	}
	return tree
}

func mustObject(t *testing.T, text string) map[string]any {
	t.Helper()
	var object map[string]any
	if err := json.Unmarshal([]byte(text), &object); err != nil {
		t.Fatal(err)
	}
	return object
}
