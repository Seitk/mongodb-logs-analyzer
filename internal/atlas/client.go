package atlas

import (
	"compress/gzip"
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const (
	DefaultBaseURL = "https://cloud.mongodb.com"
	apiVersion     = "application/vnd.atlas.2023-02-01+json"
)

type Client struct {
	BaseURL    string
	PublicKey  string
	PrivateKey string
	HTTP       *http.Client
}

type Project struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type Process struct {
	Hostname string `json:"hostname"`
	Port     int    `json:"port"`
	TypeName string `json:"typeName"`
	ID       string `json:"id"`
}

func NewClient(publicKey, privateKey string) *Client {
	return &Client{
		BaseURL:    DefaultBaseURL,
		PublicKey:  publicKey,
		PrivateKey: privateKey,
		HTTP:       &http.Client{Timeout: 5 * time.Minute},
	}
}

func (c *Client) ListProjects() ([]Project, error) {
	var all []Project
	pageNum := 1
	for {
		url := fmt.Sprintf("%s/api/atlas/v2/groups?pageNum=%d&itemsPerPage=100", c.BaseURL, pageNum)
		body, err := c.doJSON(url)
		if err != nil {
			return nil, fmt.Errorf("list projects: %w", err)
		}
		var resp struct {
			Results    []Project `json:"results"`
			TotalCount int       `json:"totalCount"`
		}
		if err := json.Unmarshal(body, &resp); err != nil {
			return nil, fmt.Errorf("parse projects: %w", err)
		}
		all = append(all, resp.Results...)
		if len(all) >= resp.TotalCount {
			break
		}
		pageNum++
	}
	return all, nil
}

func (c *Client) ListProcesses(projectID string) ([]Process, error) {
	var all []Process
	pageNum := 1
	for {
		url := fmt.Sprintf("%s/api/atlas/v2/groups/%s/processes?pageNum=%d&itemsPerPage=100", c.BaseURL, projectID, pageNum)
		body, err := c.doJSON(url)
		if err != nil {
			return nil, fmt.Errorf("list processes: %w", err)
		}
		var resp struct {
			Results    []Process `json:"results"`
			TotalCount int       `json:"totalCount"`
		}
		if err := json.Unmarshal(body, &resp); err != nil {
			return nil, fmt.Errorf("parse processes: %w", err)
		}
		all = append(all, resp.Results...)
		if len(all) >= resp.TotalCount {
			break
		}
		pageNum++
	}
	return all, nil
}

func (c *Client) DownloadLog(projectID, hostname, logName string, start, end time.Time, w io.Writer) error {
	url := fmt.Sprintf("%s/api/atlas/v2/groups/%s/clusters/%s/logs/%s.gz?startDate=%d&endDate=%d",
		c.BaseURL, projectID, hostname, logName, start.Unix(), end.Unix())

	body, err := c.doRequest(url, false)
	if err != nil {
		return fmt.Errorf("download log: %w", err)
	}
	defer body.Close()

	gz, err := gzip.NewReader(body)
	if err != nil {
		return fmt.Errorf("gzip decompress: %w", err)
	}
	defer gz.Close()

	_, err = io.Copy(w, gz)
	return err
}

func (c *Client) doJSON(url string) ([]byte, error) {
	rc, err := c.doRequest(url, true)
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	return io.ReadAll(rc)
}

func (c *Client) doRequest(url string, jsonAccept bool) (io.ReadCloser, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	if jsonAccept {
		req.Header.Set("Accept", apiVersion)
	}

	// First request — expect 401 with WWW-Authenticate
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusUnauthorized {
		if resp.StatusCode >= 400 {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
		}
		return resp.Body, nil
	}

	// Parse digest challenge and retry
	challenge := resp.Header.Get("Www-Authenticate")
	resp.Body.Close()
	if challenge == "" {
		return nil, fmt.Errorf("no WWW-Authenticate header in 401 response")
	}

	authHeader, err := c.buildDigestAuth("GET", req.URL.RequestURI(), challenge)
	if err != nil {
		return nil, fmt.Errorf("digest auth: %w", err)
	}

	req2, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	if jsonAccept {
		req2.Header.Set("Accept", apiVersion)
	}
	req2.Header.Set("Authorization", authHeader)

	resp2, err := c.HTTP.Do(req2)
	if err != nil {
		return nil, err
	}

	if resp2.StatusCode >= 400 {
		body, _ := io.ReadAll(resp2.Body)
		resp2.Body.Close()
		return nil, fmt.Errorf("HTTP %d: %s", resp2.StatusCode, string(body))
	}

	return resp2.Body, nil
}

func (c *Client) buildDigestAuth(method, uri, challenge string) (string, error) {
	params := parseDigestChallenge(challenge)
	realm := params["realm"]
	nonce := params["nonce"]
	qop := params["qop"]

	if realm == "" || nonce == "" {
		return "", fmt.Errorf("missing realm or nonce in challenge")
	}

	ha1 := md5Hash(c.PublicKey + ":" + realm + ":" + c.PrivateKey)
	ha2 := md5Hash(method + ":" + uri)

	cnonce := generateCNonce()
	nc := "00000001"

	var response string
	if strings.Contains(qop, "auth") {
		response = md5Hash(ha1 + ":" + nonce + ":" + nc + ":" + cnonce + ":" + "auth" + ":" + ha2)
	} else {
		response = md5Hash(ha1 + ":" + nonce + ":" + ha2)
	}

	header := fmt.Sprintf(`Digest username="%s", realm="%s", nonce="%s", uri="%s", response="%s"`,
		c.PublicKey, realm, nonce, uri, response)

	if strings.Contains(qop, "auth") {
		header += fmt.Sprintf(`, qop=auth, nc=%s, cnonce="%s"`, nc, cnonce)
	}

	return header, nil
}

func parseDigestChallenge(challenge string) map[string]string {
	params := make(map[string]string)
	challenge = strings.TrimPrefix(challenge, "Digest ")

	// Simple parser for key="value" pairs
	for _, part := range splitRespectingQuotes(challenge) {
		part = strings.TrimSpace(part)
		idx := strings.Index(part, "=")
		if idx < 0 {
			continue
		}
		key := strings.TrimSpace(part[:idx])
		val := strings.TrimSpace(part[idx+1:])
		val = strings.Trim(val, `"`)
		params[key] = val
	}
	return params
}

func splitRespectingQuotes(s string) []string {
	var parts []string
	var current strings.Builder
	inQuote := false
	for _, ch := range s {
		switch {
		case ch == '"':
			inQuote = !inQuote
			current.WriteRune(ch)
		case ch == ',' && !inQuote:
			parts = append(parts, current.String())
			current.Reset()
		default:
			current.WriteRune(ch)
		}
	}
	if current.Len() > 0 {
		parts = append(parts, current.String())
	}
	return parts
}

func md5Hash(s string) string {
	h := md5.Sum([]byte(s))
	return hex.EncodeToString(h[:])
}

func generateCNonce() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}
