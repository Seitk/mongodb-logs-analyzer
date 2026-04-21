package parser

import (
	"bytes"
	"encoding/json"
	"sort"
	"strings"
)

// knownCommands is the set of MongoDB command names we recognize.
var knownCommands = []string{
	"find", "aggregate", "insert", "update", "delete",
	"findAndModify", "count", "distinct", "geoNear",
	"mapReduce", "getMore", "create", "drop",
	"createIndexes", "dropIndexes", "collMod",
}

// ExtractPattern extracts a command name and normalized query shape
// from a MongoDB command object, for grouping similar slow queries.
func ExtractPattern(cmd map[string]interface{}) (name string, shape string) {
	if cmd == nil {
		return "", ""
	}

	// Identify command name
	for _, cn := range knownCommands {
		if _, ok := cmd[cn]; ok {
			name = cn
			break
		}
	}
	if name == "" {
		return "", ""
	}

	// Extract the filter/query document based on command type
	var filterDoc interface{}

	switch name {
	case "find", "count", "distinct":
		filterDoc = cmd["filter"]
	case "update":
		filterDoc = extractFirstSubdocField(cmd, "updates", "q")
	case "delete":
		filterDoc = extractFirstSubdocField(cmd, "deletes", "q")
	case "findAndModify":
		filterDoc = cmd["query"]
	case "aggregate":
		filterDoc = cmd["pipeline"]
	case "insert", "getMore", "create", "drop", "createIndexes", "dropIndexes", "collMod", "geoNear", "mapReduce":
		// No filter shape to extract
		return name, ""
	}

	if filterDoc == nil {
		return name, ""
	}

	// Handle pipeline vs filter document
	switch v := filterDoc.(type) {
	case []interface{}:
		normalized := normalizePipeline(v)
		b, err := marshalSorted(normalized)
		if err != nil {
			return name, ""
		}
		return name, string(b)
	case map[string]interface{}:
		normalized := normalizeShape(v)
		b, err := marshalSorted(normalized)
		if err != nil {
			return name, ""
		}
		return name, string(b)
	default:
		return name, ""
	}
}

// extractFirstSubdocField extracts field from the first element of an array field in cmd.
// e.g., cmd["updates"][0]["q"]
func extractFirstSubdocField(cmd map[string]interface{}, arrayKey, fieldKey string) interface{} {
	arr, ok := cmd[arrayKey].([]interface{})
	if !ok || len(arr) == 0 {
		return nil
	}
	first, ok := arr[0].(map[string]interface{})
	if !ok {
		return nil
	}
	return first[fieldKey]
}

// normalizeShape replaces leaf values with 1, preserving operator documents
// (keys starting with $) and sorting keys for deterministic output.
func normalizeShape(doc map[string]interface{}) map[string]interface{} {
	result := make(map[string]interface{})
	for k, v := range doc {
		switch val := v.(type) {
		case map[string]interface{}:
			// If this is an operator document (contains $ keys), normalize recursively
			if isOperatorDoc(val) {
				result[k] = normalizeShape(val)
			} else {
				// Non-operator nested doc: normalize recursively
				result[k] = normalizeShape(val)
			}
		default:
			// Leaf value: replace with 1
			result[k] = 1
		}
	}
	return result
}

// isOperatorDoc returns true if any key in the map starts with $.
func isOperatorDoc(doc map[string]interface{}) bool {
	for k := range doc {
		if strings.HasPrefix(k, "$") {
			return true
		}
	}
	return false
}

// normalizePipeline normalizes each stage in an aggregation pipeline,
// sorting stages for deterministic output.
func normalizePipeline(pipeline []interface{}) []interface{} {
	result := make([]interface{}, 0, len(pipeline))
	for _, stage := range pipeline {
		switch s := stage.(type) {
		case map[string]interface{}:
			normalized := normalizeShape(s)
			result = append(result, normalized)
		default:
			result = append(result, stage)
		}
	}

	// Sort pipeline stages for deterministic output
	sort.Slice(result, func(i, j int) bool {
		bi, _ := marshalSorted(result[i])
		bj, _ := marshalSorted(result[j])
		return string(bi) < string(bj)
	})

	return result
}

// marshalSorted produces JSON with sorted keys at every level.
func marshalSorted(v interface{}) ([]byte, error) {
	switch val := v.(type) {
	case map[string]interface{}:
		return marshalSortedMap(val)
	case []interface{}:
		return marshalSortedArray(val)
	default:
		return json.Marshal(v)
	}
}

func marshalSortedMap(m map[string]interface{}) ([]byte, error) {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var buf bytes.Buffer
	buf.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			buf.WriteByte(',')
		}
		keyBytes, err := json.Marshal(k)
		if err != nil {
			return nil, err
		}
		buf.Write(keyBytes)
		buf.WriteByte(':')

		valBytes, err := marshalSorted(m[k])
		if err != nil {
			return nil, err
		}
		buf.Write(valBytes)
	}
	buf.WriteByte('}')
	return buf.Bytes(), nil
}

func marshalSortedArray(arr []interface{}) ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteByte('[')
	for i, elem := range arr {
		if i > 0 {
			buf.WriteByte(',')
		}
		elemBytes, err := marshalSorted(elem)
		if err != nil {
			return nil, err
		}
		buf.Write(elemBytes)
	}
	buf.WriteByte(']')
	return buf.Bytes(), nil
}
