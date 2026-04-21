package analyzer

import (
	"testing"
)

func TestConnectionAccumulator_OpenClose(t *testing.T) {
	acc := NewConnectionAccumulator()

	e1 := makeEntry("2024-01-01T00:00:00Z", "I", "NETWORK", 22943, "connection accepted")
	e1.Attr = map[string]interface{}{"remote": "10.0.0.1:5000", "connectionId": float64(1)}
	acc.Process(e1)

	e2 := makeEntry("2024-01-01T00:00:01Z", "I", "NETWORK", 22943, "connection accepted")
	e2.Attr = map[string]interface{}{"remote": "10.0.0.2:6000", "connectionId": float64(2)}
	acc.Process(e2)

	e3 := makeEntry("2024-01-01T00:01:00Z", "I", "NETWORK", 22944, "connection ended")
	e3.Attr = map[string]interface{}{"connectionId": float64(1)}
	acc.Process(e3)

	result := acc.Result()

	if result.TotalOpened != 2 {
		t.Errorf("TotalOpened = %d, want 2", result.TotalOpened)
	}
	if result.TotalClosed != 1 {
		t.Errorf("TotalClosed = %d, want 1", result.TotalClosed)
	}
}

func TestConnectionAccumulator_PerIP(t *testing.T) {
	acc := NewConnectionAccumulator()

	for i := 0; i < 5; i++ {
		e := makeEntry("2024-01-01T00:00:00Z", "I", "NETWORK", 22943, "connection accepted")
		e.Attr = map[string]interface{}{"remote": "10.0.0.1:5000", "connectionId": float64(i + 1)}
		acc.Process(e)
	}
	for i := 0; i < 3; i++ {
		e := makeEntry("2024-01-01T00:00:00Z", "I", "NETWORK", 22943, "connection accepted")
		e.Attr = map[string]interface{}{"remote": "10.0.0.2:6000", "connectionId": float64(i + 100)}
		acc.Process(e)
	}

	result := acc.Result()

	if len(result.ByIP) != 2 {
		t.Fatalf("len(ByIP) = %d, want 2", len(result.ByIP))
	}
	if result.ByIP[0].IP != "10.0.0.1" {
		t.Errorf("ByIP[0].IP = %q, want %q", result.ByIP[0].IP, "10.0.0.1")
	}
	if result.ByIP[0].Count != 5 {
		t.Errorf("ByIP[0].Count = %d, want 5", result.ByIP[0].Count)
	}
	if result.ByIP[1].IP != "10.0.0.2" {
		t.Errorf("ByIP[1].IP = %q, want %q", result.ByIP[1].IP, "10.0.0.2")
	}
	if result.ByIP[1].Count != 3 {
		t.Errorf("ByIP[1].Count = %d, want 3", result.ByIP[1].Count)
	}
}

func TestConnectionAccumulator_Timeline(t *testing.T) {
	acc := NewConnectionAccumulator()

	// Minute 1: 2 opens
	e1 := makeEntry("2024-01-01T00:01:10Z", "I", "NETWORK", 22943, "connection accepted")
	e1.Attr = map[string]interface{}{"remote": "10.0.0.1:5000", "connectionId": float64(1)}
	acc.Process(e1)

	e2 := makeEntry("2024-01-01T00:01:30Z", "I", "NETWORK", 22943, "connection accepted")
	e2.Attr = map[string]interface{}{"remote": "10.0.0.1:5001", "connectionId": float64(2)}
	acc.Process(e2)

	// Minute 2: 1 close
	e3 := makeEntry("2024-01-01T00:02:15Z", "I", "NETWORK", 22944, "connection ended")
	e3.Attr = map[string]interface{}{"connectionId": float64(1)}
	acc.Process(e3)

	result := acc.Result()

	if len(result.Timeline) != 2 {
		t.Fatalf("len(Timeline) = %d, want 2", len(result.Timeline))
	}
	if result.Timeline[0].Opened != 2 {
		t.Errorf("Timeline[0].Opened = %d, want 2", result.Timeline[0].Opened)
	}
	if result.Timeline[1].Closed != 1 {
		t.Errorf("Timeline[1].Closed = %d, want 1", result.Timeline[1].Closed)
	}
}

func TestConnectionAccumulator_PeakConnections(t *testing.T) {
	acc := NewConnectionAccumulator()

	// Open 3 connections
	for i := 1; i <= 3; i++ {
		e := makeEntry("2024-01-01T00:00:00Z", "I", "NETWORK", 22943, "connection accepted")
		e.Attr = map[string]interface{}{"remote": "10.0.0.1:5000", "connectionId": float64(i)}
		acc.Process(e)
	}

	// Close 1
	e := makeEntry("2024-01-01T00:01:00Z", "I", "NETWORK", 22944, "connection ended")
	e.Attr = map[string]interface{}{"connectionId": float64(1)}
	acc.Process(e)

	result := acc.Result()

	if result.PeakConnections != 3 {
		t.Errorf("PeakConnections = %d, want 3", result.PeakConnections)
	}
}
