package mdrender

import (
	"strings"
	"testing"
)

const taskDoc = "# Plan\n\n- [ ] write **docs**\n- [x] ship `v1`\n  - [ ] nested [link](https://example.com)\n- plain item\n\n```\n- [ ] not a task (code)\n```\n\n> - [X] quoted task\n\n1. [ ] numbered\n"

func TestTasksIDsAndText(t *testing.T) {
	got := Tasks(taskDoc)
	want := []Task{
		{0, "write docs", false},
		{1, "ship v1", true},
		{2, "nested link", false},
		{3, "quoted task", true},
		{4, "numbered", false},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d tasks: %+v", len(got), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("task %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}

// The n-th task returned by Tasks must be the n-th checkbox in the HTML that
// recipients receive, so stored states can be applied by position.
func TestTaskIDsMatchRenderedCheckboxes(t *testing.T) {
	frag, err := RenderFragment(taskDoc)
	if err != nil {
		t.Fatal(err)
	}
	tasks := Tasks(taskDoc)
	if n := countCheckboxes(frag); n != len(tasks) {
		t.Fatalf("html has %d checkboxes, Tasks found %d\n%s", n, len(tasks), frag)
	}
	// Recipients' view: sanitize as incoming mail and apply all-true states.
	states := make([]bool, len(tasks))
	for i := range states {
		states[i] = i%2 == 0
	}
	out, _ := SanitizeIncoming(frag, false, states)
	if c := strings.Count(out, `<input type="checkbox" disabled checked>`); c != 3 {
		t.Errorf("checked boxes = %d, want 3:\n%s", c, out)
	}
	if c := strings.Count(out, `<input type="checkbox" disabled>`); c != 2 {
		t.Errorf("unchecked boxes = %d, want 2:\n%s", c, out)
	}
}

func TestNormalizeCheckboxes(t *testing.T) {
	in := `<ul><li><input type="checkbox" checked=""> a</li><li><input type="checkbox"> b</li></ul><p><input type="text" value="password"><input>x</p>`
	out, n := NormalizeCheckboxes(in, nil)
	if n != 2 || strings.Contains(out, "text") || strings.Contains(out, "password") || strings.Count(out, "<input") != 2 {
		t.Fatalf("n=%d out=%s", n, out)
	}
	if !strings.Contains(out, `<input type="checkbox" disabled checked> a`) || !strings.Contains(out, `<input type="checkbox" disabled> b`) {
		t.Fatalf("original states not kept: %s", out)
	}
	out, _ = NormalizeCheckboxes(in, []bool{false, true})
	if !strings.Contains(out, `<input type="checkbox" disabled> a`) || !strings.Contains(out, `<input type="checkbox" disabled checked> b`) {
		t.Fatalf("states not applied: %s", out)
	}
	// A state list that does not match the HTML is ignored, not misapplied.
	out, _ = NormalizeCheckboxes(in, []bool{false})
	if !strings.Contains(out, `disabled checked> a`) {
		t.Fatalf("mismatched states applied: %s", out)
	}
}

func TestSanitizeIncomingDropsFormControls(t *testing.T) {
	out, _ := SanitizeIncoming(`<form action="https://evil.test"><input type="password" name="p"><input type="checkbox" onclick="x()" checked><button>go</button></form>`, false, nil)
	if strings.Contains(out, "password") || strings.Contains(out, "onclick") || strings.Contains(out, "form") || strings.Contains(out, "button") {
		t.Fatalf("unsafe output: %s", out)
	}
	if out != `<input type="checkbox" disabled checked>go` {
		t.Fatalf("got %q", out)
	}
}

func TestTasksBounded(t *testing.T) {
	var b strings.Builder
	for i := 0; i < MaxTasks+50; i++ {
		b.WriteString("- [ ] " + strings.Repeat("x", 600) + "\n")
	}
	got := Tasks(b.String())
	if len(got) != MaxTasks {
		t.Fatalf("got %d tasks", len(got))
	}
	if len(got[0].Text) > maxTaskText+len("…") {
		t.Fatalf("text not clipped: %d", len(got[0].Text))
	}
	if len(Tasks("no tasks here")) != 0 || Tasks("") == nil {
		t.Fatal("empty handling")
	}
}
