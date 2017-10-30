package doorman

import (
	"bytes"
	"encoding/json"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/ory/ladon"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type Policy struct {
	ID          string
	Description string
}

type User struct {
	ID string
}

type Response struct {
	Allowed bool
	User    User
	Policy  Policy
}

type ErrorResponse struct {
	Message string
}

var defaultConfig = Config{
	PoliciesFilename: "../sample.yaml",
	JWTIssuer:        "",
}

func TestMain(m *testing.M) {
	//Set Gin to Test Mode
	gin.SetMode(gin.TestMode)
	// Run the other tests
	os.Exit(m.Run())
}

func loadTempFile(content []byte) error {
	tmpfile, _ := ioutil.TempFile("", "")
	defer os.Remove(tmpfile.Name()) // clean up
	tmpfile.Write(content)
	tmpfile.Close()
	_, err := New(&Config{tmpfile.Name(), ""})
	return err
}

func TestLoadPolicies(t *testing.T) {
	// Loads policies.yaml in current folder by default.
	_, err := New(&Config{"", ""})
	assert.NotNil(t, err) // doorman/policies.yaml does not exists.

	// Loads policies from env.
	os.Setenv("POLICIES_FILE", "/tmp/unknown.yaml")
	defer os.Unsetenv("POLICIES_FILE")
	_, err = New(&Config{"", ""})
	assert.NotNil(t, err)

	// Missing file
	_, err = New(&Config{"/tmp/unknown.yaml", ""})
	assert.NotNil(t, err)

	// Bad YAML
	err = loadTempFile([]byte("$\\--xx"))
	assert.NotNil(t, err)

	// Bad policies
	err = loadTempFile([]byte(`
	-
	  id: "1"
	  conditions:
	    - a
	    - b
	`))
	assert.NotNil(t, err)

	// Empty file
	err = loadTempFile([]byte(``))
	assert.Nil(t, err)

	// Duplicated ID
	err = loadTempFile([]byte(`
	-
	  id: "1"
	  effect: allow
	-
	  id: "1"
	  effect: deny
	`))
	assert.NotNil(t, err)
}

func TestReloadPolicies(t *testing.T) {
	doorman, err := New(&Config{"../sample.yaml", ""})
	assert.Nil(t, err)
	loaded, _ := doorman.Manager.GetAll(0, maxInt)
	assert.Equal(t, 5, len(loaded))

	// Second load.
	doorman.loadPolicies()
	loaded, _ = doorman.Manager.GetAll(0, maxInt)
	assert.Equal(t, 5, len(loaded))
}

func performRequest(r http.Handler, method, path string, body io.Reader) *httptest.ResponseRecorder {
	req, _ := http.NewRequest(method, path, body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func performAllowed(t *testing.T, r *gin.Engine, body io.Reader, expected int, response interface{}) {
	w := performRequest(r, "POST", "/allowed", body)
	require.Equal(t, expected, w.Code)
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.Nil(t, err)
}

func TestDoormanGet(t *testing.T) {
	r := gin.New()
	doorman, _ := New(&defaultConfig)
	SetupRoutes(r, doorman)

	w := performRequest(r, "GET", "/allowed", nil)
	assert.Equal(t, w.Code, http.StatusNotFound)
}

func TestDoormanEmpty(t *testing.T) {
	r := gin.New()
	doorman, _ := New(&defaultConfig)
	SetupRoutes(r, doorman)

	var response ErrorResponse
	performAllowed(t, r, nil, http.StatusBadRequest, &response)
	assert.Equal(t, response.Message, "Missing body")
}

func TestDoormanInvalidJSON(t *testing.T) {
	r := gin.New()
	doorman, _ := New(&defaultConfig)
	SetupRoutes(r, doorman)

	body := bytes.NewBuffer([]byte("{\"random\\;mess\"}"))
	var response ErrorResponse
	performAllowed(t, r, body, http.StatusBadRequest, &response)
	assert.Contains(t, response.Message, "invalid character ';'")
}

func TestDoormanAllowed(t *testing.T) {
	r := gin.New()
	doorman, _ := New(&defaultConfig)
	SetupRoutes(r, doorman)

	for _, request := range []*ladon.Request{
		// Policy #1
		{
			Subject:  "foo",
			Action:   "update",
			Resource: "server.org/blocklist:onecrl",
		},
		// Policy #2
		{
			Subject:  "foo",
			Action:   "update",
			Resource: "server.org/blocklist:onecrl",
			Context: ladon.Context{
				"planet": "Mars", // "mars" is case-sensitive
			},
		},
		// Policy #3
		{
			Subject:  "foo",
			Action:   "read",
			Resource: "server.org/blocklist:onecrl",
			Context: ladon.Context{
				"ip": "127.0.0.1",
			},
		},
		// Policy #4
		{
			Subject:  "bilbo",
			Action:   "wear",
			Resource: "ring",
			Context: ladon.Context{
				"owner": "bilbo",
			},
		},
		// Policy #5
		{
			Subject:  "group:admins",
			Action:   "create",
			Resource: "dns://",
			Context: ladon.Context{
				"domain": "kinto.mozilla.org",
			},
		},
	} {
		token, _ := json.Marshal(request)
		body := bytes.NewBuffer(token)
		var response Response
		performAllowed(t, r, body, http.StatusOK, &response)
		assert.Equal(t, true, response.Allowed)
	}
}

func TestDoormanNotAllowed(t *testing.T) {
	r := gin.New()
	doorman, _ := New(&defaultConfig)
	SetupRoutes(r, doorman)

	for _, request := range []*ladon.Request{
		// Policy #1
		{
			Subject:  "foo",
			Action:   "delete",
			Resource: "server.org/blocklist:onecrl",
		},
		// Policy #2
		{
			Subject:  "foo",
			Action:   "update",
			Resource: "server.org/blocklist:onecrl",
			Context: ladon.Context{
				"planet": "mars",
			},
		},
		// Policy #3
		{
			Subject:  "foo",
			Action:   "read",
			Resource: "server.org/blocklist:onecrl",
			Context: ladon.Context{
				"ip": "10.0.0.1",
			},
		},
		// Policy #4
		{
			Subject:  "gollum",
			Action:   "wear",
			Resource: "ring",
			Context: ladon.Context{
				"owner": "bilbo",
			},
		},
		// Policy #5
		{
			Subject:  "group:admins",
			Action:   "create",
			Resource: "dns://",
			Context: ladon.Context{
				"domain": "kinto-storage.org",
			},
		},
		// Default
		{},
	} {
		token, _ := json.Marshal(request)
		body := bytes.NewBuffer(token)
		var response Response
		performAllowed(t, r, body, http.StatusOK, &response)
		assert.Equal(t, false, response.Allowed)
	}
}

func TestDoormanVerifiesJWT(t *testing.T) {
	r := gin.New()
	doorman, _ := New(&Config{
		PoliciesFilename: "../sample.yaml",
		JWTIssuer:        "https://auth.mozilla.auth0.com/",
	})
	SetupRoutes(r, doorman)

	// Policy #1 will match.
	request := ladon.Request{
		Subject:  "foo",
		Action:   "delete",
		Resource: "server.org/blocklist:onecrl",
	}
	token, _ := json.Marshal(request)
	body := bytes.NewBuffer(token)
	var response ErrorResponse

	// Missing Authorization header.
	performAllowed(t, r, body, http.StatusUnauthorized, &response)
	assert.Equal(t, "Token not found", response.Message)
}
