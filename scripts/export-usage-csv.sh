#!/usr/bin/env bash
#
# Export Claude usage data to CSV files for analysis in Excel/Sheets.
#
# Produces, in the output directory (default ./exports):
#   cache_daily_activity.csv   - the stats-cache.json "Recent Activity" table
#   cache_model_totals.csv     - the stats-cache.json per-model totals
#   daily_by_model.csv         - COMPLETE current usage aggregated per day per
#                                model, parsed from the session transcripts
#                                (~/.claude/projects/**/*.jsonl). This is the one
#                                to use for trends; the cache is sparse/stale.
#
# Usage:  scripts/export-usage-csv.sh [output_dir]
# Requires: jq

set -euo pipefail

OUT_DIR="${1:-./exports}"
CLAUDE_DIR="${HOME}/.claude"
STATS="${CLAUDE_DIR}/stats-cache.json"
PROJECTS="${CLAUDE_DIR}/projects"

command -v jq >/dev/null || { echo "error: jq is required (brew install jq)"; exit 1; }
mkdir -p "$OUT_DIR"

# ── 1. stats-cache: daily activity ────────────────────────────────────────────
if [[ -f "$STATS" ]]; then
  {
    echo "date,messages,sessions,tool_calls"
    jq -r '.dailyActivity | sort_by(.date)[]
           | [.date, .messageCount, .sessionCount, .toolCallCount] | @csv' "$STATS"
  } > "$OUT_DIR/cache_daily_activity.csv"

  # ── 2. stats-cache: per-model totals ────────────────────────────────────────
  {
    echo "model,input_tokens,output_tokens,cache_read_tokens,cache_creation_tokens,web_search_requests,cost_usd"
    jq -r '.modelUsage | to_entries[]
           | [.key, .value.inputTokens, .value.outputTokens,
              .value.cacheReadInputTokens, .value.cacheCreationInputTokens,
              .value.webSearchRequests, .value.costUSD] | @csv' "$STATS"
  } > "$OUT_DIR/cache_model_totals.csv"
  echo "wrote cache_daily_activity.csv, cache_model_totals.csv"
else
  echo "note: $STATS not found — skipping cache exports"
fi

# ── 3. transcripts: complete daily usage per model ────────────────────────────
#
# Per-token USD rates (input/output), $/MTok, from Anthropic's published API
# pricing. Cache writes/reads aren't priced separately per model — they're a
# standard multiplier off the input rate (~1.25x write, ~0.1x read; see
# shared/prompt-caching.md in the claude-api skill). Update INPUT/OUTPUT below
# if Anthropic repricing makes a model here stale; unmatched model ids fall
# through to "unknown" and get an empty cost_usd rather than a wrong number.
RATE_TABLE='[
  {"pattern": "opus-5",        "input": 5.00,  "output": 25.00},
  {"pattern": "mythos-5-1",    "input": 10.00, "output": 50.00},
  {"pattern": "fable-5-1",     "input": 10.00, "output": 50.00},
  {"pattern": "mythos-5",      "input": 10.00, "output": 50.00},
  {"pattern": "fable-5",       "input": 10.00, "output": 50.00},
  {"pattern": "opus-4-8",      "input": 5.00,  "output": 25.00},
  {"pattern": "opus-4-7",      "input": 5.00,  "output": 25.00},
  {"pattern": "opus-4-6",      "input": 5.00,  "output": 25.00},
  {"pattern": "opus-4-5",      "input": 5.00,  "output": 25.00},
  {"pattern": "opus-4-1",      "input": 15.00, "output": 75.00},
  {"pattern": "opus-4-0",      "input": 15.00, "output": 75.00},
  {"pattern": "opus-4-20250514","input": 15.00,"output": 75.00},
  {"pattern": "sonnet-5",      "input": 2.00,  "output": 10.00},
  {"pattern": "sonnet-4-6",    "input": 3.00,  "output": 15.00},
  {"pattern": "sonnet-4-5",    "input": 3.00,  "output": 15.00},
  {"pattern": "sonnet-4-0",    "input": 3.00,  "output": 15.00},
  {"pattern": "sonnet-4-20250514","input": 3.00,"output": 15.00},
  {"pattern": "3-7-sonnet",    "input": 3.00,  "output": 15.00},
  {"pattern": "3-5-sonnet",    "input": 3.00,  "output": 15.00},
  {"pattern": "haiku-4-5",     "input": 1.00,  "output": 5.00},
  {"pattern": "3-5-haiku",     "input": 0.80,  "output": 4.00},
  {"pattern": "3-haiku",       "input": 0.25,  "output": 1.25},
  {"pattern": "3-opus",        "input": 15.00, "output": 75.00}
]'
CACHE_WRITE_MULTIPLIER=1.25
CACHE_READ_MULTIPLIER=0.1

if [[ -d "$PROJECTS" ]]; then
  # 'agent' splits main session work from subagent (Task tool) work via
  # isSidechain. 'thinking_blocks' counts extended-thinking blocks as a rough
  # effort proxy — Claude Code does NOT record the configured effort level.
  {
    echo "date,model,agent,messages,input_tokens,output_tokens,cache_read_tokens,cache_creation_tokens,web_search_requests,thinking_blocks,cost_usd"
    find "$PROJECTS" -name '*.jsonl' -print0 \
      | xargs -0 cat \
      | jq -c 'select(.type=="assistant" and (.message.usage != null))
               | {date: (.timestamp[0:10]),
                  model: (.message.model // "unknown"),
                  agent: (if (.isSidechain // false) then "subagent" else "main" end),
                  thinking: ((.message.content // []) | map(select(.type=="thinking")) | length),
                  u: .message.usage}' \
      | jq -s --argjson rates "$RATE_TABLE" \
             --argjson cacheWrite "$CACHE_WRITE_MULTIPLIER" \
             --argjson cacheRead "$CACHE_READ_MULTIPLIER" -r '
          def rate($model): ($rates | map(select(.pattern as $p | $model | contains($p))) | first);
          group_by(.date + "|" + .model + "|" + .agent)
          | map({
              date: .[0].date,
              model: .[0].model,
              agent: .[0].agent,
              messages: length,
              input: (map(.u.input_tokens // 0) | add),
              output: (map(.u.output_tokens // 0) | add),
              cache_read: (map(.u.cache_read_input_tokens // 0) | add),
              cache_creation: (map(.u.cache_creation_input_tokens // 0) | add),
              web_search: (map(.u.server_tool_use.web_search_requests // 0) | add),
              thinking: (map(.thinking) | add)
            })
          | map(. + {rate: rate(.model)})
          | map(. + {
              cost: (if .rate == null then null else
                (.input * .rate.input
                 + .output * .rate.output
                 + .cache_creation * .rate.input * $cacheWrite
                 + .cache_read * .rate.input * $cacheRead) / 1000000
              end)
            })
          | sort_by(.date, .model, .agent)[]
          | [.date, .model, .agent, .messages, .input, .output, .cache_read, .cache_creation, .web_search, .thinking,
             (if .cost == null then "" else (.cost * 10000 | round / 10000) end)]
          | @csv'
  } > "$OUT_DIR/daily_by_model.csv"
  echo "wrote daily_by_model.csv ($(( $(wc -l < "$OUT_DIR/daily_by_model.csv") - 1 )) rows)"
else
  echo "note: $PROJECTS not found — skipping transcript export"
fi

echo "done -> $OUT_DIR"
