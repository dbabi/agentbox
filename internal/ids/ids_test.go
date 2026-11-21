package ids

import "testing"

func TestNew(t *testing.T) {
	seen := map[string]bool{}
	for _, k := range Kinds {
		for i := 0; i < 1000; i++ {
			id := New(k)
			if !Is(k, id) || seen[id] {
				t.Fatalf("New(%q) = %q: malformed or repeated", k, id)
			}
			seen[id] = true
		}
	}
	// C-G1: a hand-made id like T42 is never a task id.
	for _, s := range []string{"T42", "task_T42", "task_", "task_8ZZZZZZZZZZZZZZZZZZZZZZZZZ", "task_0000000000000000000000000I",
		"TASK_00000000000000000000000000", "dn_00000000000000000000000000\n", "x_00000000000000000000000000"} {
		if Valid(s) {
			t.Errorf("Valid(%q)", s)
		}
	}
	if Is(Task, New(Message)) {
		t.Error("a message id passes as a task id")
	}
}

func TestTimeOrder(t *testing.T) {
	a := New(Task)
	b := New(Task)
	if a[:15] > b[:15] { // the first 10 ULID digits are the millisecond time
		t.Fatalf("%s sorts after %s", a, b)
	}
}
