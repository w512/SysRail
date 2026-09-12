package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/w512/SysRail/internal/client"
	"github.com/w512/SysRail/internal/core/audit"
)

func runAudit(args []string, stdout, stderr io.Writer) int {
	fs, socket, asJSON := adminFlags("audit", stderr)
	limit := fs.Int("limit", 50, "number of most recent records")
	agent := fs.String("agent", "", "only records for this agent")
	capability := fs.String("capability", "", "only records for this capability")
	requestID := fs.String("request", "", "only records for this request ID")
	follow := fs.Bool("follow", false, "keep printing new records")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	c, err := adminClient(*socket)
	if err != nil {
		fmt.Fprintln(stderr, "sysrail:", err)
		return 1
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	q := url.Values{}
	q.Set("limit", strconv.Itoa(*limit))
	for k, v := range map[string]string{"agent": *agent, "capability": *capability, "request_id": *requestID} {
		if v != "" {
			q.Set(k, v)
		}
	}
	recs, err := fetchAudit(ctx, c, q)
	if err != nil {
		fmt.Fprintln(stderr, "sysrail:", err)
		return 1
	}
	tw := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
	if !*asJSON {
		fmt.Fprintln(tw, "ID\tTIME\tEVENT\tAGENT\tCAPABILITY\tRESOURCE\tDECISION\tRESULT\tDETAIL")
	}
	var last int64
	emit := func(recs []audit.Record) {
		for _, r := range recs {
			last = r.ID
			if *asJSON {
				printJSON(stdout, r)
				continue
			}
			detail := r.ErrorCode
			if r.ErrorMessage != "" {
				detail += ": " + r.ErrorMessage
			}
			if r.Actor != "" {
				detail = "by " + r.Actor
			}
			if r.RequestID != "" && detail == "" {
				detail = r.RequestID
			}
			fmt.Fprintf(tw, "%d\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", r.ID, r.Time.Local().Format(time.DateTime),
				r.Event, dash(r.Agent), dash(r.Capability), dash(r.Resource), dash(r.PolicyDecision), r.Result, detail)
		}
		tw.Flush()
	}
	emit(recs)
	if !*follow {
		return 0
	}
	for {
		select {
		case <-ctx.Done():
			return 0
		case <-time.After(time.Second):
		}
		q.Set("after_id", strconv.FormatInt(last, 10))
		q.Set("limit", "1000")
		recs, err := fetchAudit(ctx, c, q)
		if err != nil {
			if ctx.Err() != nil {
				return 0
			}
			fmt.Fprintln(stderr, "sysrail:", err)
			return 1
		}
		emit(recs)
	}
}

func fetchAudit(ctx context.Context, c *client.Client, q url.Values) ([]audit.Record, error) {
	var out struct {
		Records []audit.Record `json:"records"`
	}
	_, err := c.Do(ctx, http.MethodGet, "/v1/audit?"+q.Encode(), nil, &out)
	return out.Records, err
}
