package main

import (
	"context"
	"encoding/json/v2"
	"fmt"
	"io"
	"net/http"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/natscell/mesh"
	"github.com/TerraScale/ts-orchestrator/internal/regionmember"
	"github.com/TerraScale/ts-orchestrator/internal/releasepush"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "member promote:", err)
		os.Exit(1)
	}
}

func run() error {
	if len(os.Args) != 2 || !slices.Contains([]string{"gru", "sjc", "fra"}, os.Args[1]) {
		return fmt.Errorf("usage: member-promote <gru|sjc|fra>")
	}
	region := os.Args[1]
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	token, err := releasepush.MintTokenFor(ctx, releasepush.PromoteAudience+region)
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+region+"."+mesh.Domain+releasepush.MemberPromotePath, strings.NewReader("{}"))
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bearer "+token)
	response, err := (&http.Client{Timeout: 3 * time.Minute}).Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	var reply regionmember.Reply
	if err := json.UnmarshalRead(io.LimitReader(response.Body, 1<<20), &reply); err != nil {
		return fmt.Errorf("HTTP %d: %w", response.StatusCode, err)
	}
	if reply.Promotion != nil {
		fmt.Printf("%s: promoted %s to voting manager %d of 3\n", region, reply.Promotion.Hostname, reply.Promotion.Voters)
	}
	if reply.Region != "" {
		fmt.Printf("%s Raft leader %s\n", reply.Region, reply.Leader)
		if err := reply.Members.Write(os.Stdout); err != nil {
			return err
		}
	}
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d: %s", response.StatusCode, reply.Error)
	}
	return nil
}
