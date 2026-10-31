package event

import "testing"

func TestFieldResolvesNamedFieldsAndRaw(t *testing.T) {
	e := Event{
		Image:            "/usr/bin/cat",
		CommandLine:      "cat /etc/shadow",
		ParentImage:      "/usr/bin/bash",
		TargetFilename:   "/etc/shadow",
		User:             "root",
		CurrentDirectory: "/home/u",
		Raw:              map[string]string{"Extra": "x"},
	}
	cases := []struct {
		field   string
		wantVal string
		wantOK  bool
	}{
		{"Image", "/usr/bin/cat", true},
		{"CommandLine", "cat /etc/shadow", true},
		{"ParentImage", "/usr/bin/bash", true},
		{"TargetFilename", "/etc/shadow", true},
		{"User", "root", true},
		{"CurrentDirectory", "/home/u", true},
		{"Extra", "x", true},
		{"Nope", "", false},
	}
	for _, c := range cases {
		got, ok := e.Field(c.field)
		if got != c.wantVal || ok != c.wantOK {
			t.Errorf("Field(%q) = (%q, %v), want (%q, %v)", c.field, got, ok, c.wantVal, c.wantOK)
		}
	}
}

func TestFieldEmptyFieldReportsAbsent(t *testing.T) {
	var e Event
	if v, ok := e.Field("Image"); v != "" || ok {
		t.Errorf("empty Image: got (%q, %v), want (\"\", false)", v, ok)
	}
	// A Raw entry that is explicitly the empty string is still "present".
	e.Raw = map[string]string{"K": ""}
	if v, ok := e.Field("K"); v != "" || !ok {
		t.Errorf("present-but-empty Raw K: got (%q, %v), want (\"\", true)", v, ok)
	}
}
