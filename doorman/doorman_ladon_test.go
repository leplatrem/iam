package doorman

import (
	"bytes"
	"os"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

var sampleConfigs ServicesConfig

func TestMain(m *testing.M) {
	// Load sample policies once
	sampleConfigs = ServicesConfig{
		ServiceConfig{
			Service:   "https://sample.yaml",
			JWTIssuer: "",
			Tags: Tags{
				"admins": Principals{"userid:maria"},
			},
			Policies: Policies{
				Policy{
					ID:         "1",
					Principals: Principals{"userid:foo", "tag:admins"},
					Actions:    []string{"update"},
					Resources:  []string{"<.*>"},
					Effect:     "allow",
				},
				Policy{
					ID:         "2",
					Principals: Principals{"<.*>"},
					Actions:    []string{"<.*>"},
					Resources:  []string{"<.*>"},
					Conditions: Conditions{
						"planet": Condition{
							Type: "StringEqualCondition",
							Options: map[string]interface{}{
								"equals": "mars",
							},
						},
					},
					Effect: "deny",
				},
				Policy{
					ID:         "3",
					Principals: Principals{"<.*>"},
					Actions:    []string{"read"},
					Resources:  []string{"<.*>"},
					Conditions: Conditions{
						"ip": Condition{
							Type: "CIDRCondition",
							Options: map[string]interface{}{
								"cidr": "127.0.0.0/8",
							},
						},
					},
					Effect: "allow",
				},
				Policy{
					ID:         "4",
					Principals: Principals{"<.*>"},
					Actions:    []string{"<.*>"},
					Resources:  []string{"<.*>"},
					Conditions: Conditions{
						"owner": Condition{
							Type: "MatchPrincipalsCondition",
						},
					},
					Effect: "allow",
				},
				Policy{
					ID:         "5",
					Principals: Principals{"group:admins"},
					Actions:    []string{"create"},
					Resources:  []string{"<.*>"},
					Conditions: Conditions{
						"domain": Condition{
							Type: "StringMatchCondition",
							Options: map[string]interface{}{
								"matches": ".*\\.mozilla\\.org",
							},
						},
					},
					Effect: "allow",
				},
				Policy{
					ID:         "6",
					Principals: Principals{"role:editor"},
					Actions:    []string{"update"},
					Resources:  []string{"pto"},
					Effect:     "allow",
				},
			},
		},
	}
	//Set Gin to Test Mode
	gin.SetMode(gin.TestMode)
	// Run the other tests
	os.Exit(m.Run())
}

func sampleDoorman() *LadonDoorman {
	doorman := NewDefaultLadon()
	doorman.LoadPolicies(sampleConfigs)
	return doorman
}

func TestBadServicesConfig(t *testing.T) {
	d := NewDefaultLadon()

	// Duplicated policy ID
	err := d.LoadPolicies(ServicesConfig{
		ServiceConfig{
			Service: "a",
			Policies: Policies{
				Policy{
					ID:     "1",
					Effect: "allow",
				},
				Policy{
					ID:     "1",
					Effect: "deny",
				},
			},
		},
	})
	assert.NotNil(t, err)

	// Duplicated service
	err = d.LoadPolicies(ServicesConfig{
		ServiceConfig{
			Service: "a",
			Policies: Policies{
				Policy{
					ID:     "1",
					Effect: "allow",
				},
			},
		},
		ServiceConfig{
			Service: "a",
			Policies: Policies{
				Policy{
					ID:     "1",
					Effect: "allow",
				},
			},
		},
	})
	assert.NotNil(t, err)

	// Bad JWT issuer
	err = d.LoadPolicies(ServicesConfig{
		ServiceConfig{
			JWTIssuer: "http://perlin-pinpin",
		},
	})
	assert.NotNil(t, err)

	// Unknown condition type
	err = d.LoadPolicies(ServicesConfig{
		ServiceConfig{
			Service: "a",
			Policies: Policies{
				Policy{
					ID: "1",
					Conditions: Conditions{
						"owner": Condition{
							Type: "healthy",
						},
					},
					Effect: "allow",
				},
			},
		},
	})
	assert.NotNil(t, err)
}

func TestLoadPoliciesTwice(t *testing.T) {
	doorman := sampleDoorman()
	loaded, _ := doorman.ladons["https://sample.yaml"].Manager.GetAll(0, maxInt)
	assert.Equal(t, 6, len(loaded))

	// Second load.
	doorman.LoadPolicies(sampleConfigs)
	loaded, _ = doorman.ladons["https://sample.yaml"].Manager.GetAll(0, maxInt)
	assert.Equal(t, 6, len(loaded))

	// Load bad policies, does not affect existing.
	err := doorman.LoadPolicies(ServicesConfig{
		ServiceConfig{
			JWTIssuer: "http://perlin-pinpin",
		},
	})
	assert.Contains(t, err.Error(), "issuer \"http://perlin-pinpin\" not supported or has bad format")
	_, ok := doorman.ladons["https://sample.yaml"]
	assert.True(t, ok)
}

func TestIsAllowed(t *testing.T) {
	doorman := sampleDoorman()

	// Policy #1
	request := &Request{
		Principals: Principals{"userid:foo"},
		Action:     "update",
		Resource:   "server.org/blocklist:onecrl",
	}

	// Check service
	allowed := doorman.IsAllowed("https://sample.yaml", request)
	assert.True(t, allowed)
	allowed = doorman.IsAllowed("https://bad.service", request)
	assert.False(t, allowed)
}

func TestExpandPrincipals(t *testing.T) {
	doorman := sampleDoorman()

	// Expand principals from tags
	principals := doorman.ExpandPrincipals("https://sample.yaml", Principals{"userid:maria"})
	assert.Equal(t, principals, Principals{"userid:maria", "tag:admins"})
}

func TestDoormanAllowed(t *testing.T) {
	doorman := sampleDoorman()

	for _, request := range []*Request{
		// Policy #1
		{
			Principals: []string{"userid:foo"},
			Action:     "update",
			Resource:   "server.org/blocklist:onecrl",
		},
		// Policy #2
		{
			Principals: []string{"userid:foo"},
			Action:     "update",
			Resource:   "server.org/blocklist:onecrl",
			Context: Context{
				"planet": "Mars", // "mars" is case-sensitive
			},
		},
		// Policy #3
		{
			Principals: []string{"userid:foo"},
			Action:     "read",
			Resource:   "server.org/blocklist:onecrl",
			Context: Context{
				"ip": "127.0.0.1",
			},
		},
		// Policy #4
		{
			Principals: []string{"userid:bilbo"},
			Action:     "wear",
			Resource:   "ring",
			Context: Context{
				"owner": "userid:bilbo",
			},
		},
		// Policy #4 (list of principals)
		{
			Principals: []string{"userid:bilbo"},
			Action:     "wear",
			Resource:   "ring",
			Context: Context{
				"owner": []string{"userid:alice", "userid:bilbo"},
			},
		},
		// Policy #5
		{
			Principals: []string{"group:admins"},
			Action:     "create",
			Resource:   "dns://",
			Context: Context{
				"domain": "kinto.mozilla.org",
			},
		},
	} {
		assert.Equal(t, true, doorman.IsAllowed("https://sample.yaml", request))
	}
}

func TestDoormanNotAllowed(t *testing.T) {
	doorman := sampleDoorman()

	for _, request := range []*Request{
		// Policy #1
		{
			Principals: []string{"userid:foo"},
			Action:     "delete",
			Resource:   "server.org/blocklist:onecrl",
			Context:    Context{},
		},
		// Policy #2
		{
			Principals: []string{"userid:foo"},
			Action:     "update",
			Resource:   "server.org/blocklist:onecrl",
			Context: Context{
				"planet": "mars",
			},
		},
		// Policy #3
		{
			Principals: []string{"userid:foo"},
			Action:     "read",
			Resource:   "server.org/blocklist:onecrl",
			Context: Context{
				"ip": "10.0.0.1",
			},
		},
		// Policy #4
		{
			Principals: []string{"userid:gollum"},
			Action:     "wear",
			Resource:   "ring",
			Context: Context{
				"owner": "bilbo",
			},
		},
		// Policy #5
		{
			Principals: []string{"group:admins"},
			Action:     "create",
			Resource:   "dns://",
			Context: Context{
				"domain": "kinto-storage.org",
			},
		},
		// Default
		{
			Context: Context{},
		},
	} {
		// Force context value like in handler.
		request.Context["_principals"] = request.Principals
		assert.Equal(t, false, doorman.IsAllowed("https://sample.yaml", request))
	}
}

func TestDoormanAuditLogger(t *testing.T) {
	doorman := sampleDoorman()

	var buf bytes.Buffer
	doorman.auditLogger().logger.Out = &buf
	defer func() {
		doorman.auditLogger().logger.Out = os.Stdout
	}()

	// Logs when service is bad.
	doorman.IsAllowed("bad service", &Request{})
	assert.Contains(t, buf.String(), "\"allowed\":false")

	service := "https://sample.yaml"

	// Logs policies.
	buf.Reset()
	doorman.IsAllowed(service, &Request{
		Principals: Principals{"userid:any"},
		Action:     "any",
		Resource:   "any",
		Context: Context{
			"planet":      "mars",
			"_principals": Principals{"userid:any"},
		},
	})
	assert.Contains(t, buf.String(), "\"allowed\":false")
	assert.Contains(t, buf.String(), "\"policies\":[\"2\"]")

	buf.Reset()
	doorman.IsAllowed(service, &Request{
		Principals: Principals{"userid:foo"},
		Action:     "update",
		Resource:   "server.org/blocklist:onecrl",
	})
	assert.Contains(t, buf.String(), "\"allowed\":true")
	assert.Contains(t, buf.String(), "\"policies\":[\"1\"]")
}
