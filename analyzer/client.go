package analyzer

import (
	"fmt"
	"sort"

	"github.com/anthropics/mla/parser"
)

// ClientGroup holds stats for a driver/version/app group.
type ClientGroup struct {
	DriverName    string
	DriverVersion string
	AppName       string
	Count         int
	UniqueIPs     map[string]struct{}
}

// ClientResult holds all client metadata results.
type ClientResult struct {
	Groups []ClientGroup
}

// ClientAccumulator tracks client metadata.
type ClientAccumulator struct {
	groups map[string]*ClientGroup
}

// NewClientAccumulator creates a new ClientAccumulator.
func NewClientAccumulator() *ClientAccumulator {
	return &ClientAccumulator{
		groups: make(map[string]*ClientGroup),
	}
}

// Process processes a client metadata entry (ID 51800).
func (c *ClientAccumulator) Process(entry parser.LogEntry) {
	if entry.ID != 51800 {
		return
	}

	doc := entry.AttrMap("doc")
	if doc == nil {
		return
	}

	var driverName, driverVersion, appName string

	if driverMap, ok := doc["driver"].(map[string]interface{}); ok {
		if n, ok := driverMap["name"].(string); ok {
			driverName = n
		}
		if v, ok := driverMap["version"].(string); ok {
			driverVersion = v
		}
	}

	if appMap, ok := doc["application"].(map[string]interface{}); ok {
		if n, ok := appMap["name"].(string); ok {
			appName = n
		}
	}

	key := fmt.Sprintf("%s|%s|%s", driverName, driverVersion, appName)

	grp, exists := c.groups[key]
	if !exists {
		grp = &ClientGroup{
			DriverName:    driverName,
			DriverVersion: driverVersion,
			AppName:       appName,
			UniqueIPs:     make(map[string]struct{}),
		}
		c.groups[key] = grp
	}

	grp.Count++

	remote := entry.AttrString("remote")
	if remote != "" {
		ip := extractIP(remote)
		grp.UniqueIPs[ip] = struct{}{}
	}
}

// Result returns the client metadata results.
func (c *ClientAccumulator) Result() ClientResult {
	groups := make([]ClientGroup, 0, len(c.groups))
	for _, grp := range c.groups {
		groups = append(groups, *grp)
	}
	sort.Slice(groups, func(i, j int) bool {
		return groups[i].Count > groups[j].Count
	})
	return ClientResult{Groups: groups}
}
