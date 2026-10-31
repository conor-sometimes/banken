package parser

import (
	"strings"
	"testing"
	"time"

	"github.com/conor-sometimes/banken/internal/event"
)

// A real Sysmon EventID 1 (Process Create) record as Windows Event Log XML,
// the shape `wevtutil qe` and `Get-WinEvent | % { $_.ToXml() }` produce.
const sysmonProcessCreate = `<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Sysmon' Guid='{5770385f-c22a-43e0-bf4c-06f5698ffbd9}'/><EventID>1</EventID><Version>5</Version><Level>4</Level><Task>1</Task><Opcode>0</Opcode><Keywords>0x8000000000000000</Keywords><TimeCreated SystemTime='2026-10-31T21:00:00.1234567Z'/><EventRecordID>12345</EventRecordID><Correlation/><Execution ProcessID='1480' ThreadID='5612'/><Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>WIN-DEV</Computer><Security UserID='S-1-5-18'/></System><EventData><Data Name='RuleName'>-</Data><Data Name='UtcTime'>2026-10-31 21:00:00.123</Data><Data Name='ProcessGuid'>{a1b2}</Data><Data Name='ProcessId'>4242</Data><Data Name='Image'>C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Data><Data Name='CommandLine'>powershell.exe -nop -w hidden -enc ZQBjAGgAbwA=</Data><Data Name='CurrentDirectory'>C:\Users\dev\</Data><Data Name='User'>WIN-DEV\dev</Data><Data Name='IntegrityLevel'>Medium</Data><Data Name='Hashes'>SHA256=ABC123</Data><Data Name='ParentProcessId'>1000</Data><Data Name='ParentImage'>C:\Windows\explorer.exe</Data><Data Name='ParentCommandLine'>explorer.exe</Data></EventData></Event>`

func TestSysmonParse(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  []event.Event
	}{
		{
			name:  "process create maps onto the common fields; the rest go to Raw",
			input: sysmonProcessCreate,
			want: []event.Event{{
				Source:           "sysmon",
				Time:             time.Date(2026, 10, 31, 21, 0, 0, 123456700, time.UTC),
				Image:            `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
				CommandLine:      "powershell.exe -nop -w hidden -enc ZQBjAGgAbwA=",
				ParentImage:      `C:\Windows\explorer.exe`,
				CurrentDirectory: `C:\Users\dev\`,
				User:             `WIN-DEV\dev`,
				PID:              4242,
				PPID:             1000,
				Raw: map[string]string{
					"RuleName":          "-",
					"UtcTime":           "2026-10-31 21:00:00.123",
					"ProcessGuid":       "{a1b2}",
					"IntegrityLevel":    "Medium",
					"Hashes":            "SHA256=ABC123",
					"ParentCommandLine": "explorer.exe",
					"EventID":           "1",
					"Computer":          "WIN-DEV",
				},
			}},
		},
		{
			// EventID 11 FileCreate: TargetFilename is a first-class field, so a
			// Sigma file_event rule matches it like a Linux PATH record.
			name: "file create fills TargetFilename",
			input: `<Event><System><Provider Name='Microsoft-Windows-Sysmon'/><EventID>11</EventID><TimeCreated SystemTime='2026-10-31T21:01:00Z'/><Computer>WIN-DEV</Computer></System>` +
				`<EventData><Data Name='Image'>C:\tmp\dropper.exe</Data><Data Name='TargetFilename'>C:\Users\dev\AppData\Roaming\evil.exe</Data></EventData></Event>`,
			want: []event.Event{{
				Source:         "sysmon",
				Time:           time.Date(2026, 10, 31, 21, 1, 0, 0, time.UTC),
				Image:          `C:\tmp\dropper.exe`,
				TargetFilename: `C:\Users\dev\AppData\Roaming\evil.exe`,
				Raw:            map[string]string{"EventID": "11", "Computer": "WIN-DEV"},
			}},
		},
		{
			name:  "two events in one stream, order kept; a malformed tail is dropped",
			input: sysmonProcessCreate + "\n" + sysmonProcessCreate + "\n<Event><System><EventID>oops",
			want:  nil, // filled below
		},
		{
			name:  "not XML at all yields nothing, never an error",
			input: "this is not xml\n{\"json\":true}\n",
			want:  nil,
		},
		{
			name:  "empty input",
			input: "",
			want:  nil,
		},
	}

	p := Sysmon{}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := parseString(t, p, c.input)
			if c.name == "two events in one stream, order kept; a malformed tail is dropped" {
				if len(got) != 2 {
					t.Fatalf("want 2 events (the malformed third dropped), got %d", len(got))
				}
				return
			}
			assertEvents(t, got, c.want)
		})
	}
}

func TestSysmonNeverPanics(t *testing.T) {
	// A grab-bag of broken inputs: the parser must return, never panic.
	for _, in := range []string{
		"<Event>", "<Event></Event>", "<Event><System><EventID>x</EventID></System></Event>",
		"<<<<", "<Event><EventData><Data/></EventData></Event>",
		"<Event><EventData><Data Name='ProcessId'>notanumber</Data></EventData></Event>",
		strings.Repeat("<Event>", 1000),
	} {
		_, _ = Sysmon{}.Parse(strings.NewReader(in))
	}
}
