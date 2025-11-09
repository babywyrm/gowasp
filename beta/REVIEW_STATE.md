# Review State Management

The review state management system allows you to maintain context across review sessions and resume reviews where you left off.

## Features

- **Directory Fingerprinting**: Automatically detects if codebase matches a previous review
- **Checkpoint System**: Saves progress at key stages (prioritization, deep dive, synthesis)
- **Context Files**: Generates human-readable context files for Cursor/Claude
- **Resume Capability**: Pick up where you left off with a previous review

## Usage

### Enable Review State Tracking

```bash
python3 smart__.py /path/to/repo "your question" --enable-review-state
```

This will:
- Create a new review state
- Check if directory structure matches a previous review
- Save checkpoints at each stage
- Generate context files

### List All Reviews

```bash
python3 smart__.py . --list-reviews
```

Shows all available reviews with their status.

### Check Review Status

```bash
python3 smart__.py . --review-status {review_id}
```

Shows detailed information about a specific review.

### Resume a Review

```bash
python3 smart__.py /path/to/repo "your question" --resume-review {review_id}
```

Resumes a previous review. You can optionally use the previous question.

## How It Works

### Directory Fingerprinting

The system computes a hash based on:
- File paths
- File sizes
- Modification times

If the directory structure matches exactly, it will detect and offer to resume the review.

### Review State Files

Reviews are stored in `.scrynet_cache/reviews/`:

- `{review_id}.json` - Structured review state (machine-readable)
- `_{review_id}_context.md` - Human-readable context for Cursor/Claude

### Checkpoints

Checkpoints are saved at:
1. **Prioritization** - After files are prioritized
2. **Deep Dive** - After file analysis completes
3. **Synthesis** - After synthesis is generated

## Context Files for Cursor/Claude

The context files (`.md` format) contain:
- Review metadata
- Progress summary
- Files analyzed
- Findings summary
- Next steps

You can open these files in Cursor to provide context for AI assistance.

## Non-Breaking

This feature is **completely optional**:
- Existing workflow unchanged if you don't use the flags
- No impact on performance when disabled
- All review state is stored in cache directory (already gitignored)

## Scrynet

Scrynet is the AI-powered code analysis system that powers this review state management. The name reflects its ability to "scry" (see into) code to reveal security issues and insights.

## Example Workflow

1. Start a review with state tracking:
   ```bash
   python3 smart__.py . "security review" --enable-review-state
   ```

2. Review gets interrupted or you need to stop

3. Later, resume the review:
   ```bash
   python3 smart__.py . --resume-review abc123
   ```

4. Or let it auto-detect:
   ```bash
   python3 smart__.py . "security review" --enable-review-state
   # Will prompt if matching review found
   ```

## Integration with Cursor

The context files are designed to be read by Cursor/Claude:
- Open `_{review_id}_context.md` in Cursor
- Use it to provide context when asking questions about the review
- The structured format helps maintain context across sessions

