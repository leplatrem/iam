package ladon

import (
	"encoding/json"
	"reflect"

	"github.com/pkg/errors"
)

// Condition either do or do not fulfill an access request.
type Condition interface {
	// GetName returns the condition's name.
	GetName() string

	// Fulfills returns true if the request is fulfilled by the condition.
	Fulfills(interface{}, *Request) bool
}

// Conditions is a collection of conditions.
type Conditions map[string]Condition

type mapType map[string]interface{}

type sCondition struct {
	Type    string  `json:"type"`
	Options mapType `json:"options"`
}

// AddCondition adds a condition to the collection.
func (cs Conditions) AddCondition(key string, c Condition) {
	cs[key] = c
}

// MarshalJSON marshals a list of conditions to json.
func (cs Conditions) MarshalJSON() ([]byte, error) {
	out := make(map[string]*sCondition, len(cs))
	for k, c := range cs {
		// Convert condition struct (options) to `mapType`
		structValue := reflect.ValueOf(c).Elem()
		structType := structValue.Type()
		options := make(mapType, structValue.NumField())
		for i := 0; i < structValue.NumField(); i++ {
			structField := structType.FieldByIndex([]int{i})
			options[structField.Tag.Get("json")] = structField
		}

		out[k] = &sCondition{
			Type:    c.GetName(),
			Options: options,
		}
	}

	return json.Marshal(out)
}

// UnmarshalJSON unmarshals a list of conditions from json.
func (cs Conditions) UnmarshalJSON(data []byte) error {
	return cs.unmarshalGeneric(func(out interface{}) error {
		return json.Unmarshal(data, out)
	})
}

// UnmarshalYAML unmarshals a list of conditions from YAML.
func (cs Conditions) UnmarshalYAML(unmarshal func(interface{}) error) error {
	return cs.unmarshalGeneric(unmarshal)
}

func (cs Conditions) unmarshalGeneric(unmarshal func(interface{}) error) error {
	if cs == nil {
		return errors.New("Can not be nil")
	}
	var jcs map[string]sCondition
	var dc Condition

	if err := unmarshal(&jcs); err != nil {
		return errors.WithStack(err)
	}

	for k, jc := range jcs {
		var found bool
		for name, c := range ConditionFactories {
			if name == jc.Type {
				found = true
				dc = c()
				// Set condition struct values (options) from `mapType`.
				structValue := reflect.ValueOf(dc).Elem()
				structType := structValue.Type()
				for optionField, optionValue := range jc.Options {
					// Find the struct field associated to this option.
					structField := structValue.FieldByNameFunc(func(f string) bool {
						field, _ := structType.FieldByName(f)
						return field.Tag.Get("json") == optionField
					})
					if structField.IsValid() {
						structField.Set(reflect.ValueOf(optionValue))
					}
				}
				cs.AddCondition(k, dc)
				break
			}
		}

		if !found {
			return errors.Errorf("Could not find condition type %s", jc.Type)
		}
	}

	return nil
}

// ConditionFactories is where you can add custom conditions
var ConditionFactories = map[string]func() Condition{
	new(StringEqualCondition).GetName(): func() Condition {
		return new(StringEqualCondition)
	},
	new(CIDRCondition).GetName(): func() Condition {
		return new(CIDRCondition)
	},
	new(EqualsSubjectCondition).GetName(): func() Condition {
		return new(EqualsSubjectCondition)
	},
	new(StringPairsEqualCondition).GetName(): func() Condition {
		return new(StringPairsEqualCondition)
	},
	new(StringMatchCondition).GetName(): func() Condition {
		return new(StringMatchCondition)
	},
}
