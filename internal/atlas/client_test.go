package atlas

import (
	"compress/gzip"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestParseDigestChallenge(t *testing.T) {
	challenge := `Digest realm="MMS Public API", nonce="abc123", qop="auth", algorithm=MD5`
	params := parseDigestChallenge(challenge)

	if params["realm"] != "MMS Public API" {
		t.Errorf("realm = %q, want %q", params["realm"], "MMS Public API")
	}
	if params["nonce"] != "abc123" {
		t.Errorf("nonce = %q, want %q", params["nonce"], "abc123")
	}
	if params["qop"] != "auth" {
		t.Errorf("qop = %q, want %q", params["qop"], "auth")
	}
}

func TestBuildDigestAuth(t *testing.T) {
	c := NewClient("testpub", "testpriv")
	challenge := `Digest realm="MMS Public API", nonce="testnonce", qop="auth"`

	header, err := c.buildDigestAuth("GET", "/api/atlas/v2/groups", challenge)
	if err != nil {
		t.Fatalf("buildDigestAuth error: %v", err)
	}

	if !strings.HasPrefix(header, "Digest ") {
		t.Errorf("header missing Digest prefix: %q", header)
	}
	if !strings.Contains(header, `username="testpub"`) {
		t.Errorf("header missing username: %q", header)
	}
	if !strings.Contains(header, `realm="MMS Public API"`) {
		t.Errorf("header missing realm: %q", header)
	}
	if !strings.Contains(header, "qop=auth") {
		t.Errorf("header missing qop: %q", header)
	}
}

func TestListProjects(t *testing.T) {
	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		if callCount == 1 {
			w.Header().Set("Www-Authenticate", `Digest realm="test", nonce="n1", qop="auth"`)
			w.WriteHeader(401)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"results":[{"id":"proj1","name":"My Project"}],"totalCount":1}`))
	}))
	defer srv.Close()

	c := NewClient("pub", "priv")
	c.BaseURL = srv.URL

	projects, err := c.ListProjects()
	if err != nil {
		t.Fatalf("ListProjects error: %v", err)
	}
	if len(projects) != 1 {
		t.Fatalf("got %d projects, want 1", len(projects))
	}
	if projects[0].ID != "proj1" {
		t.Errorf("project ID = %q, want %q", projects[0].ID, "proj1")
	}
	if projects[0].Name != "My Project" {
		t.Errorf("project name = %q, want %q", projects[0].Name, "My Project")
	}
}

func TestListProcesses(t *testing.T) {
	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		if callCount == 1 {
			w.Header().Set("Www-Authenticate", `Digest realm="test", nonce="n1", qop="auth"`)
			w.WriteHeader(401)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"results":[{"hostname":"shard-00-00.abc.mongodb.net","port":27017,"typeName":"REPLICA_PRIMARY","id":"shard-00-00.abc.mongodb.net:27017"}],"totalCount":1}`))
	}))
	defer srv.Close()

	c := NewClient("pub", "priv")
	c.BaseURL = srv.URL

	procs, err := c.ListProcesses("proj1")
	if err != nil {
		t.Fatalf("ListProcesses error: %v", err)
	}
	if len(procs) != 1 {
		t.Fatalf("got %d processes, want 1", len(procs))
	}
	if procs[0].TypeName != "REPLICA_PRIMARY" {
		t.Errorf("typeName = %q, want %q", procs[0].TypeName, "REPLICA_PRIMARY")
	}
}

func TestDownloadLog(t *testing.T) {
	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		if callCount == 1 {
			w.Header().Set("Www-Authenticate", `Digest realm="test", nonce="n1", qop="auth"`)
			w.WriteHeader(401)
			return
		}
		w.Header().Set("Content-Type", "application/gzip")
		gz := gzip.NewWriter(w)
		gz.Write([]byte(`{"t":{"$date":"2026-01-01T00:00:00.000Z"},"s":"I","c":"-","id":1,"ctx":"test","msg":"hello"}` + "\n"))
		gz.Close()
	}))
	defer srv.Close()

	c := NewClient("pub", "priv")
	c.BaseURL = srv.URL

	var buf strings.Builder
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	end := time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)

	err := c.DownloadLog("proj1", "host1", "mongodb", start, end, &buf)
	if err != nil {
		t.Fatalf("DownloadLog error: %v", err)
	}

	if !strings.Contains(buf.String(), `"msg":"hello"`) {
		t.Errorf("downloaded log missing expected content: %q", buf.String())
	}
}
