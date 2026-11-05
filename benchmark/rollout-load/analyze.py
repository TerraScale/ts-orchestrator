#!/usr/bin/env python3
"""Report every offered request, including time spent waiting for its scheduled start.

Events is JSONL with {"kind":"rollout_start"|"rollout_end", "rollout":1, "at":unix_seconds}.
No retry or warmup sample is silently discarded from a rollout window.
"""
import argparse
import collections
import json
import math
from pathlib import Path


def offered(row):
    return row.get('offered_at', row['started_at'])


def summarize(samples, start, end):
    cells = []
    for region in ('gru', 'sjc', 'fra'):
        for operation in ('write', 'read'):
            selected = [row for row in samples if row['region'] == region and row['kind'] == operation
                        and start <= offered(row) <= end]
            if not selected:
                cells.append({'region': region, 'operation': operation, 'requests': 0, 'pass': False})
                continue
            times = sorted(row['ms'] for row in selected)
            successes = sorted(row['completed_at'] for row in selected if row['ok'])
            failed = sum(not row['ok'] for row in selected)
            sequences = {row['sequence'] for row in selected}
            missed_records = max(sequences) - min(sequences) + 1 - len(sequences)
            p99 = times[math.ceil(len(times) * .99) - 1]
            cells.append({'region': region, 'operation': operation, 'requests': len(selected),
                          'failed': failed, 'statuses': dict(collections.Counter(str(row['status']) for row in selected)),
                          'missing_offer_records': missed_records,
                          'p99_ms': p99, 'max_ms': times[-1],
                          'max_success_gap_ms': max((b - a for a, b in zip(successes, successes[1:])), default=0) * 1000,
                          'pass': failed == 0 and missed_records == 0 and len(sequences) == len(selected) and p99 < 500})
    return cells


def main():
    parser = argparse.ArgumentParser(__doc__)
    parser.add_argument('input', type=Path)
    parser.add_argument('--events', type=Path, required=True)
    args = parser.parse_args()
    rows = [json.loads(line) for line in args.input.read_text().splitlines() if line.strip()]
    events = [json.loads(line) for line in args.events.read_text().splitlines() if line.strip()]
    samples = [row for row in rows if row.get('kind') in ('read', 'write')]
    results = []
    for start in (row for row in events if row['kind'] == 'rollout_start'):
        end = next(row for row in events if row['kind'] == 'rollout_end' and row['rollout'] == start['rollout'])
        # Capture normal operation before the stop and a full minute after rollout completion.
        through = end['at'] + 60
        coverage = True
        for region in ('gru', 'sjc', 'fra'):
            for operation in ('write', 'read'):
                stream = [offered(row) for row in samples if row['region'] == region and row['kind'] == operation]
                coverage = coverage and bool(stream) and min(stream) <= start['at'] - 10 and max(stream) >= through
        cells = summarize(samples, start['at'] - 10, through)
        recovery = []
        for region in ('gru', 'sjc', 'fra'):
            region_rows = [row for row in samples if row['region'] == region
                           and row['completed_at'] >= end['at'] and offered(row) <= through]
            failures = [row['completed_at'] for row in region_rows if not row['ok']]
            recovered = max(0, max(failures, default=end['at']) - end['at'])
            recovery.append({'region': region, 'seconds_after_end': recovered,
                             'post_rollout_failures': len(failures), 'observation_seconds': 60})
        results.append({'rollout': start['rollout'], 'start': start['at'], 'end': end['at'],
                        'complete_coverage': bool(coverage), 'cells': cells, 'recovery': recovery,
                        'pass': bool(coverage) and all(cell['pass'] for cell in cells)})
    inventories = {row['region']: row for row in rows if row.get('kind') == 'inventory'}
    exact = all(inventories.get(region, {}).get('exact', False) for region in ('gru', 'sjc', 'fra'))
    cleanup = any(row.get('kind') == 'cleanup' and row.get('status') in (204, 404) for row in rows)
    print(json.dumps({'rollouts': results, 'exact_inventory': exact, 'cleanup_confirmed': cleanup,
                      'pass': len(results) == 3 and all(row['pass'] for row in results) and exact and cleanup}, indent=2))


if __name__ == '__main__':
    main()
