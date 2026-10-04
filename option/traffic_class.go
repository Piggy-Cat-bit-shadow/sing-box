package option

import (
	"context"

	"github.com/sagernet/sing-box/common/trafficclass"
	"github.com/sagernet/sing-box/schema"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json"
)

// TrafficClassPolicy is the CONFIGURATION-side traffic class.
//
// # Why this is not just the runtime enum
//
// The runtime enum's zero value is ClassDefault, so on its own it cannot distinguish these four
// intents:
//
//	absent                    -> fall through to automatic tag detection
//	"traffic_class": "default" -> stop automatic detection for this outbound
//	"traffic_class": "interactive"
//	"traffic_class": "bulk"
//
// The difference between the first two is load-bearing. An operator who writes "default" is saying
// "do not infer anything here", which is exactly how an outbound whose tag happens to contain an
// AI keyword is excluded from the policy. Representing all four as one uint8 would make
// "explicitly default" unreachable.
//
// The envelope therefore carries a *TrafficClassPolicy: nil is unset, and a non-nil value is an
// explicit choice whatever it names. Only the resolved class reaches the flow metadata; the
// runtime layers never see this type.
type TrafficClassPolicy struct {
	Class trafficclass.Class
}

// IsDefault reports whether the policy is the explicit default.
func (p TrafficClassPolicy) IsDefault() bool {
	return p.Class.IsDefault()
}

func (p TrafficClassPolicy) MarshalJSON() ([]byte, error) {
	return json.Marshal(p.Class.String())
}

func (p *TrafficClassPolicy) UnmarshalJSON(content []byte) error {
	var value string
	if err := json.Unmarshal(content, &value); err != nil {
		return E.Cause(err, "traffic_class must be a string")
	}
	// Parse rejects an unknown name, so a typo fails the configuration instead of silently
	// disabling the policy. It accepts "" as default, which is how `"traffic_class": ""` and a
	// JSON null behave rather than becoming two more spellings of unset.
	class, err := trafficclass.Parse(value)
	if err != nil {
		return err
	}
	p.Class = class
	return nil
}

func (p TrafficClassPolicy) DescribeSchema(builder schema.Builder) (*schema.Node, error) {
	return schema.StringEnum("default", "interactive", "bulk", "realtime"), nil
}

// MarshalJSONContext and UnmarshalJSONContext are the context-aware forms the configuration
// loader uses. They exist because the option package's other types are decoded through the
// context-aware codec, which would otherwise bypass the plain methods above.
func (p TrafficClassPolicy) MarshalJSONContext(ctx context.Context) ([]byte, error) {
	return p.MarshalJSON()
}

func (p *TrafficClassPolicy) UnmarshalJSONContext(ctx context.Context, content []byte) error {
	return p.UnmarshalJSON(content)
}
