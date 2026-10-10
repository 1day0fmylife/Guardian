// guardian-maintenance previews or applies bounded, audited telemetry retention.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/1day0fmylife/Guardian/internal/store"
)

func main() {
	before := flag.String("before", "", "required past UTC RFC3339 cutoff")
	limit := flag.Int("limit", 1000, "maximum rows, 1–10000")
	dryRun := flag.Bool("dry-run", true, "preview only; use --dry-run=false to apply")
	flag.Parse()
	cutoff, err := time.Parse(time.RFC3339, *before)
	if err != nil {
		fmt.Fprintln(os.Stderr, "a valid --before RFC3339 cutoff is required")
		os.Exit(2)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	st, err := store.Open(ctx, os.Getenv("GUARDIAN_DATABASE_URL"))
	if err != nil {
		fmt.Fprintln(os.Stderr, "database unavailable")
		os.Exit(1)
	}
	defer st.Close()
	// Use existing schema; maintenance must not race application migrations.
	result, err := st.PruneDeviceTelemetry(ctx, cutoff, *limit, *dryRun)
	if err != nil {
		fmt.Fprintln(os.Stderr, "retention failed; check cutoff, batch limit and database readiness")
		os.Exit(1)
	}
	if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
		os.Exit(1)
	}
}
