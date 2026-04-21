package analyzer

import (
	"testing"
)

func TestSlowQueryAccumulator_Grouping(t *testing.T) {
	acc := NewSlowQueryAccumulator()

	// Group 1: find on db.users with filter {age:1}
	e1 := makeEntry("2024-01-01T00:00:00Z", "I", "COMMAND", 51803, "Slow query")
	e1.Attr = map[string]interface{}{
		"ns":             "db.users",
		"type":           "command",
		"durationMillis": float64(200),
		"command":        map[string]interface{}{"find": "users", "filter": map[string]interface{}{"age": 25}},
	}
	acc.Process(e1)

	// Same group: same pattern, different value
	e2 := makeEntry("2024-01-01T00:01:00Z", "I", "COMMAND", 51803, "Slow query")
	e2.Attr = map[string]interface{}{
		"ns":             "db.users",
		"type":           "command",
		"durationMillis": float64(400),
		"command":        map[string]interface{}{"find": "users", "filter": map[string]interface{}{"age": 30}},
	}
	acc.Process(e2)

	// Group 2: aggregate on db.orders
	e3 := makeEntry("2024-01-01T00:02:00Z", "I", "COMMAND", 51803, "Slow query")
	e3.Attr = map[string]interface{}{
		"ns":             "db.orders",
		"type":           "command",
		"durationMillis": float64(500),
		"command":        map[string]interface{}{"aggregate": "orders", "pipeline": []interface{}{}},
	}
	acc.Process(e3)

	// Group 2 again
	e4 := makeEntry("2024-01-01T00:03:00Z", "I", "COMMAND", 51803, "Slow query")
	e4.Attr = map[string]interface{}{
		"ns":             "db.orders",
		"type":           "command",
		"durationMillis": float64(300),
		"command":        map[string]interface{}{"aggregate": "orders", "pipeline": []interface{}{}},
	}
	acc.Process(e4)

	result := acc.Result()

	if len(result.Groups) != 2 {
		t.Fatalf("len(Groups) = %d, want 2", len(result.Groups))
	}

	// Groups are sorted by SumMs desc
	// Group 2 (aggregate): 500+300=800
	// Group 1 (find): 200+400=600
	if result.Groups[0].CmdName != "aggregate" {
		t.Errorf("Groups[0].CmdName = %q, want %q", result.Groups[0].CmdName, "aggregate")
	}
	if result.Groups[0].SumMs != 800 {
		t.Errorf("Groups[0].SumMs = %d, want 800", result.Groups[0].SumMs)
	}
	if result.Groups[0].Count != 2 {
		t.Errorf("Groups[0].Count = %d, want 2", result.Groups[0].Count)
	}

	if result.Groups[1].CmdName != "find" {
		t.Errorf("Groups[1].CmdName = %q, want %q", result.Groups[1].CmdName, "find")
	}
	if result.Groups[1].MinMs != 200 {
		t.Errorf("Groups[1].MinMs = %d, want 200", result.Groups[1].MinMs)
	}
	if result.Groups[1].MaxMs != 400 {
		t.Errorf("Groups[1].MaxMs = %d, want 400", result.Groups[1].MaxMs)
	}
	if result.Groups[1].MeanMs != 300 {
		t.Errorf("Groups[1].MeanMs = %d, want 300", result.Groups[1].MeanMs)
	}
}

func TestSlowQueryAccumulator_P95(t *testing.T) {
	acc := NewSlowQueryAccumulator()

	// Add 100 entries with durations 1..100
	for i := 1; i <= 100; i++ {
		e := makeEntry("2024-01-01T00:00:00Z", "I", "COMMAND", 51803, "Slow query")
		e.Attr = map[string]interface{}{
			"ns":             "db.coll",
			"type":           "command",
			"durationMillis": float64(i),
			"command":        map[string]interface{}{"find": "coll", "filter": map[string]interface{}{"x": 1}},
		}
		acc.Process(e)
	}

	result := acc.Result()
	if len(result.Groups) != 1 {
		t.Fatalf("len(Groups) = %d, want 1", len(result.Groups))
	}

	p95 := result.Groups[0].P95Ms
	// P95 of 1..100: rank = 0.95 * 99 = 94.05 → index 94 → value 95
	if p95 != 95 {
		t.Errorf("P95Ms = %d, want 95", p95)
	}
}

func TestSlowQueryAccumulator_Timeline(t *testing.T) {
	acc := NewSlowQueryAccumulator()

	// Minute 1
	e1 := makeEntry("2024-01-01T00:01:10Z", "I", "COMMAND", 51803, "Slow query")
	e1.Attr = map[string]interface{}{
		"ns": "db.c", "type": "command", "durationMillis": float64(100),
		"command": map[string]interface{}{"find": "c", "filter": map[string]interface{}{"a": 1}},
	}
	acc.Process(e1)

	e2 := makeEntry("2024-01-01T00:01:30Z", "I", "COMMAND", 51803, "Slow query")
	e2.Attr = map[string]interface{}{
		"ns": "db.c", "type": "command", "durationMillis": float64(100),
		"command": map[string]interface{}{"find": "c", "filter": map[string]interface{}{"a": 1}},
	}
	acc.Process(e2)

	// Minute 2
	e3 := makeEntry("2024-01-01T00:02:15Z", "I", "COMMAND", 51803, "Slow query")
	e3.Attr = map[string]interface{}{
		"ns": "db.c", "type": "command", "durationMillis": float64(100),
		"command": map[string]interface{}{"find": "c", "filter": map[string]interface{}{"a": 1}},
	}
	acc.Process(e3)

	result := acc.Result()

	if len(result.Timeline) != 2 {
		t.Fatalf("len(Timeline) = %d, want 2", len(result.Timeline))
	}
	if result.Timeline[0].Count != 2 {
		t.Errorf("Timeline[0].Count = %d, want 2", result.Timeline[0].Count)
	}
	if result.Timeline[1].Count != 1 {
		t.Errorf("Timeline[1].Count = %d, want 1", result.Timeline[1].Count)
	}
}
