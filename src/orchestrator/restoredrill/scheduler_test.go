package restoredrill

import (
	"context"
	"errors"
	"testing"
	"time"
)

type unavailableRunJournal struct {
	JournalPort
	loads int
}

func (j *unavailableRunJournal) LoadRun(context.Context, string) (RunRecord, bool, error) {
	j.loads++
	return RunRecord{}, false, errors.New("journal unavailable")
}

func TestTickerSchedulerReturnsUnrecordedDrillFailure(t *testing.T) {
	drill, _, _, journal, pager := drillFixture()
	unavailable := &unavailableRunJournal{JournalPort: journal}
	drill.journal = unavailable
	drill.scheduler = TickerScheduler{}
	drill.config.DailyInterval = time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	err := drill.Start(ctx)
	if err == nil || errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("unrecorded journal failure did not stop scheduling: %v", err)
	}
	if unavailable.loads != 1 {
		t.Fatalf("scheduler retried an unhandled failure %d times", unavailable.loads)
	}
	if len(journal.runs) != 0 || len(pager.pages) != 0 {
		t.Fatal("fixture no longer represents failure before durable recording and paging")
	}
}

func TestStartReconcilesCurrentDayBeforeScheduling(t *testing.T) {
	drill, backup, _, journal, _ := drillFixture()
	scheduler := &fakeScheduler{}
	drill.scheduler = scheduler

	if err := drill.Start(context.Background()); err != nil {
		t.Fatalf("Start = %v", err)
	}

	const runID = "restore-drill-2026-09-04"
	run, found := journal.runs[runID]
	if !found || run.Status != RunSucceeded {
		t.Fatalf("current day was not reconciled: found=%t run=%+v", found, run)
	}
	if len(backup.restores) == 0 {
		t.Fatal("current-day reconciliation did not execute a restore")
	}
	if scheduler.callback == nil || scheduler.interval != drill.config.DailyInterval {
		t.Fatal("daily scheduler was not installed after reconciliation")
	}
	if _, found := journal.runs["restore-drill-2026-09-03"]; found {
		t.Fatal("start fabricated a successful historical run")
	}
}
