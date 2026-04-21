package parser

import (
	"testing"
)

func TestExtractPattern_SimpleFilter(t *testing.T) {
	cmd := map[string]interface{}{
		"find":   "users",
		"filter": map[string]interface{}{"email": "test@example.com"},
	}

	name, shape := ExtractPattern(cmd)
	if name != "find" {
		t.Errorf("name = %q, want %q", name, "find")
	}
	expected := `{"email":1}`
	if shape != expected {
		t.Errorf("shape = %q, want %q", shape, expected)
	}
}

func TestExtractPattern_NestedOperators(t *testing.T) {
	cmd := map[string]interface{}{
		"find": "orders",
		"filter": map[string]interface{}{
			"status": map[string]interface{}{"$in": []interface{}{"pending", "active"}},
			"amount": map[string]interface{}{"$gt": 100.0},
		},
	}

	name, shape := ExtractPattern(cmd)
	if name != "find" {
		t.Errorf("name = %q, want %q", name, "find")
	}
	expected := `{"amount":{"$gt":1},"status":{"$in":1}}`
	if shape != expected {
		t.Errorf("shape = %q, want %q", shape, expected)
	}
}

func TestExtractPattern_Update(t *testing.T) {
	cmd := map[string]interface{}{
		"update": "users",
		"updates": []interface{}{
			map[string]interface{}{
				"q": map[string]interface{}{"_id": "abc123"},
				"u": map[string]interface{}{"$set": map[string]interface{}{"name": "new"}},
			},
		},
	}

	name, shape := ExtractPattern(cmd)
	if name != "update" {
		t.Errorf("name = %q, want %q", name, "update")
	}
	expected := `{"_id":1}`
	if shape != expected {
		t.Errorf("shape = %q, want %q", shape, expected)
	}
}

func TestExtractPattern_Insert(t *testing.T) {
	cmd := map[string]interface{}{
		"insert":    "users",
		"documents": []interface{}{map[string]interface{}{"name": "alice"}},
	}

	name, shape := ExtractPattern(cmd)
	if name != "insert" {
		t.Errorf("name = %q, want %q", name, "insert")
	}
	if shape != "" {
		t.Errorf("shape = %q, want empty string", shape)
	}
}

func TestExtractPattern_Aggregate(t *testing.T) {
	cmd := map[string]interface{}{
		"aggregate": "orders",
		"pipeline": []interface{}{
			map[string]interface{}{"$match": map[string]interface{}{"status": "active"}},
			map[string]interface{}{"$group": map[string]interface{}{"_id": "$userId", "total": map[string]interface{}{"$sum": "$amount"}}},
		},
	}

	name, shape := ExtractPattern(cmd)
	if name != "aggregate" {
		t.Errorf("name = %q, want %q", name, "aggregate")
	}
	expected := `[{"$group":{"_id":1,"total":{"$sum":1}}},{"$match":{"status":1}}]`
	if shape != expected {
		t.Errorf("shape = %q, want %q", shape, expected)
	}
}

func TestExtractPattern_SortedKeys(t *testing.T) {
	cmd := map[string]interface{}{
		"find": "collection",
		"filter": map[string]interface{}{
			"z_field": "z",
			"a_field": "a",
			"m_field": "m",
		},
	}

	name, shape := ExtractPattern(cmd)
	if name != "find" {
		t.Errorf("name = %q, want %q", name, "find")
	}
	expected := `{"a_field":1,"m_field":1,"z_field":1}`
	if shape != expected {
		t.Errorf("shape = %q, want %q", shape, expected)
	}
}

func TestExtractPattern_EmptyCommand(t *testing.T) {
	name, shape := ExtractPattern(nil)
	if name != "" {
		t.Errorf("name = %q, want empty string", name)
	}
	if shape != "" {
		t.Errorf("shape = %q, want empty string", shape)
	}
}
