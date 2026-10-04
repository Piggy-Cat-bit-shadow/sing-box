package option

import (
	"reflect"
	"slices"

	"github.com/sagernet/sing-box/schema"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json/badjson"
)

type schemaTypeRegistry interface {
	OptionTypes() []string
	CreateOptions(itemType string) (any, bool)
}

func registryUnion(builder schema.Builder, registry schemaTypeRegistry, excludeTypes []string, withTag bool) (*schema.Node, error) {
	var variants []*schema.Node
	for _, itemType := range registry.OptionTypes() {
		if slices.Contains(excludeTypes, itemType) {
			continue
		}
		optionsValue, _ := registry.CreateOptions(itemType)
		describer, isDescriber := optionsValue.(schema.Describer)
		var variant *schema.Node
		var err error
		if isDescriber {
			variant, err = describer.DescribeSchema(builder)
		} else {
			variant = schema.StrictObject()
			err = builder.FlattenStruct(variant, reflect.TypeOf(optionsValue).Elem())
		}
		if err != nil {
			return nil, E.Cause(err, itemType)
		}
		err = prependTypeTag(variant, itemType, withTag)
		if err != nil {
			return nil, E.Cause(err, itemType)
		}
		variants = append(variants, variant)
	}
	return schema.OneOf(variants...), nil
}

// prependTypeTag merges the polymorphic base fields into a variant produced
// from registry options, matching badjson.UnmarshallExcluded composition.
func prependTypeTag(variant *schema.Node, typeName string, withTag bool) error {
	if variant.OneOf != nil {
		for _, branch := range variant.OneOf {
			err := prependTypeTag(branch, typeName, withTag)
			if err != nil {
				return err
			}
		}
		return nil
	}
	if variant.Properties == nil {
		return E.New("cannot merge type into non-object variant")
	}
	newProperties := new(badjson.TypedMap[string, *schema.Node])
	newProperties.Put("type", schema.StringConst(typeName))
	if withTag {
		newProperties.Put("tag", schema.StringNode())
		// TrafficClass rides the polymorphic base, exactly as type and tag do, because it is
		// declared on the shared envelope and excluded from every concrete options type by the
		// same compose step. Documenting it here keeps the generated schema matching what the
		// decoder actually accepts.
		newProperties.Put("traffic_class", schema.StringEnum("default", "interactive", "bulk", "realtime"))
	}
	for _, entry := range variant.Properties.Entries() {
		newProperties.Put(entry.Key, entry.Value)
	}
	variant.Properties = newProperties
	variant.Required = append([]string{"type"}, variant.Required...)
	return nil
}
