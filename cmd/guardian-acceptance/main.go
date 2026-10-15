// guardian-acceptance evaluates an X-01/X-02 report JSON file and exits 0 only
// for a complete 18/18 PASS run on a valid pinned manifest.
package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/1day0fmylife/Guardian/internal/acceptance"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: guardian-acceptance report.json")
		os.Exit(2)
	}
	b, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	var r acceptance.Report
	if err := json.Unmarshal(b, &r); err != nil {
		fmt.Fprintln(os.Stderr, "invalid report:", err)
		os.Exit(2)
	}
	s := acceptance.Evaluate(r)
	fmt.Println(s)
	for _, p := range s.Problems {
		fmt.Println("problem:", p)
	}
	if !s.Complete {
		os.Exit(1)
	}
}
