package cache

import (
	"fmt"

	"go.mongodb.org/mongo-driver/v2/bson"
)

// Claims are the verified claims of a presentation. Read from BSON, each
// object is a map[string]any and each array a []any, the types JSON
// decoding gives, so a claim reads the same from every store.
type Claims map[string]any

// UnmarshalBSONValue reads a BSON document. BSON null leaves the claims
// unset.
func (c *Claims) UnmarshalBSONValue(typ byte, data []byte) error {
	switch bson.Type(typ) {
	case bson.TypeNull:
		*c = nil
		return nil
	case bson.TypeEmbeddedDocument:
	default:
		return fmt.Errorf("cache: verified claims are a BSON document, not a %s", bson.Type(typ))
	}
	var document bson.D
	if err := bson.UnmarshalValue(bson.TypeEmbeddedDocument, data, &document); err != nil {
		return fmt.Errorf("cache: verified claims: %w", err)
	}
	*c = claimsObject(document)
	return nil
}

// claimsObject returns a decoded BSON document as an object.
func claimsObject(document bson.D) map[string]any {
	object := make(map[string]any, len(document))
	for _, element := range document {
		object[element.Key] = claimValue(element.Value)
	}
	return object
}

// claimValue returns a decoded BSON value with each document in it as an
// object and each array as a []any.
func claimValue(value any) any {
	switch typed := value.(type) {
	case bson.D:
		return claimsObject(typed)
	case bson.A:
		array := make([]any, len(typed))
		for i, item := range typed {
			array[i] = claimValue(item)
		}
		return array
	}
	return value
}
