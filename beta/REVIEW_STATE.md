# Review State and Cache (Beta)

This guide explains how to preserve context across sessions, resume prior reviews, and manage the beta cache. It applies only to the beta analyzer (`gowasp/beta/smart__.py`).

## What you get
- Persistent review state with checkpoints (prioritization, deep dive, synthesis)
- Human-readable context files for Cursor/Claude
- Namespaced cache per repo/model to speed up repeated runs
- CLI tools to list, resume, and manage reviews and cache

---

## Quick Start

1) Start a review with state tracking

```bash
python3 smart__.py /path/to/repo "your question" --enable-review-state
```

2) Resume a prior review

- By ID:
```bash
python3 smart__.py /path/to/repo --resume-review <review_id>
```
- Auto-detect by directory (same repo structure):
```bash
python3 smart__.py /path/to/repo "your question" --enable-review-state
# If a matching review exists, you'll be prompted to resume
```

3) List and inspect reviews

```bash
# List available reviews (most recent first)
python3 smart__.py . --list-reviews

# Show status of a specific review
python3 smart__.py . --review-status <review_id>
```

4) Open the saved context in your editor

```
.scrynet_cache/reviews/_<review_id>_context.md
```
Use this as a prompt anchor in Cursor/Claude to maintain continuity.

---

## How Review State matching works

- Matching relies on a directory fingerprint (stable hash of paths, file sizes, and mtimes).
- If you run from the same repo path (or one with the same structure), `--enable-review-state` will detect an existing review and prompt to resume.
- You can always resume explicitly with `--resume-review <review_id>` regardless of path.

---

## Checkpoints saved
- Prioritization: which files were selected
- Deep dive: findings collected and files analyzed
- Synthesis: final report string and lengths

These are visible in the status and in the context file under `.scrynet_cache/reviews/`.

---

## Cache (performance) vs Review State (continuity)

- Review State = continuity for humans and AI: checkpoints, context markdown, resume flow.
- Cache = performance for repeated prompts: stores API responses, auto-reused when inputs match.

They are separate but complementary:
- Review state files are under: `.scrynet_cache/reviews/`
- Cache entries are under namespaced folders: `.scrynet_cache/<repo_fingerprint>/<model>/`

---

## Cache Management Commands

All commands exit after performing the requested action.

```bash
# Show cache statistics
python3 smart__.py . --cache-info

# List recent cache entries
python3 smart__.py . --cache-list

# Prune entries older than N days
python3 smart__.py . --cache-prune 14

# Clear all cache entries (beta cache only)
python3 smart__.py . --cache-clear

# Export a manifest (paths + content preview) to a JSON file
python3 smart__.py . --cache-export cache_manifest.json
```

### Namespacing details
- Cache is namespaced by (repo_fingerprint, model)
- Keys are SHA256 of: `stage|file|prompt`
- If fingerprinting cannot be computed, a fallback hash of `repo_path` is used

---

## End-to-End Testing Checklist

1) Populate cache & create a review
```bash
python3 smart__.py /path/to/repo "security quick pass" --enable-review-state
```
Expect: analysis runs; Review ID printed; `.scrynet_cache/` created.

2) Verify review exists
```bash
python3 smart__.py . --list-reviews
python3 smart__.py . --review-status <review_id>
```

3) Validate cache reuse
```bash
python3 smart__.py /path/to/repo "security quick pass" --enable-review-state
```
Expect: "Cache hit" messages for stages on repeat runs.

4) Inspect cache
```bash
python3 smart__.py . --cache-info
python3 smart__.py . --cache-list
```

5) Prune/Clear
```bash
python3 smart__.py . --cache-prune 7
python3 smart__.py . --cache-clear
```

6) Auto-detect resume
```bash
python3 smart__.py /path/to/repo "security quick pass" --enable-review-state
# If a matching review exists, you'll be prompted to resume
```

---

## Troubleshooting

- "No reviews found": You ran without `--enable-review-state`. Start a review with that flag or resume by ID.
- Cache grows large: use `--cache-prune 30` monthly; export a manifest via `--cache-export` if you need auditing.
- Different path, same repo: `--resume-review <review_id>` always works; `--enable-review-state` will only auto-detect if fingerprints match.
- Bypass cache: add `--no-cache` to force fresh API calls.

