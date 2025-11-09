# Beta Directory Improvement Plan

## Critical Issues (High Priority)

### 1. Import Path Issue
**Problem**: `from prompts import PromptFactory` fails when script is run from outside the beta directory.

**Solution**: 
- Use relative import: `from .prompts import PromptFactory` (if making it a package)
- Or add path resolution: `sys.path.insert(0, str(Path(__file__).parent))`

**Impact**: Scripts currently fail when run from different directories.

---

### 2. Model Inconsistency
**Problem**: README claims "Claude 3.5 Sonnet" but `smart__.py` uses `claude-3-5-haiku-20241022`.

**Solution**: 
- Update README to reflect actual model usage
- Or change code to use Sonnet for consistency
- Document why Haiku vs Sonnet choice

**Impact**: User confusion and potential performance/quality differences.

---

### 3. Missing Dependencies File
**Problem**: No `requirements.txt` for easy setup.

**Solution**: Create `requirements.txt` with pinned versions:
```
anthropic>=0.18.0
rich>=13.0.0
```

**Impact**: Harder for users to set up the environment.

---

## Important Improvements (Medium Priority)

### 4. Error Handling
**Current Issues**:
- API failures can crash the entire analysis
- No retry logic for transient failures
- Malformed JSON responses aren't handled gracefully

**Solution**:
- Add retry decorator with exponential backoff
- Better error messages with actionable guidance
- Fallback behavior when API calls fail

---

### 5. Cost Tracking
**Problem**: No visibility into API usage or estimated costs.

**Solution**:
- Track input/output tokens per API call
- Display cost estimates (Haiku: ~$0.25/$1.25 per 1M tokens)
- Add `--estimate-cost` flag to show costs before running

---

### 6. Code Duplication
**Duplicated Code**:
- File scanning logic (3 implementations)
- JSON parsing (3 implementations)
- Output formatting (overlapping code)

**Solution**:
- Create `common.py` with shared utilities:
  - `scan_repo_files()` function
  - `parse_json_response()` function
  - `get_api_key()` function
  - Constants (SKIP_DIRS, CODE_EXTS, etc.)

---

### 7. Configuration & Validation
**Missing**:
- Input validation (question length, file path safety)
- Configurable rate limits
- Better handling of edge cases (empty repos, no findings)

**Solution**:
- Add validation functions
- Make rate limiting configurable
- Better user feedback for edge cases

---

## Nice-to-Have Improvements (Low Priority)

### 8. Better Progress Indicators
- Add progress bars for all long operations
- Show ETA for analysis completion
- Display current stage clearly

### 9. Testing
- Unit tests for core functions
- Integration tests with mock API responses
- Example outputs in `examples/` directory

### 10. Documentation
- Usage examples for each script
- Comparison guide: when to use which tool
- Architecture diagram
- API cost estimation guide

### 11. Code Quality
- Type hints everywhere (some missing)
- Docstrings for all public functions
- Consistent code style (consider black formatter)

### 12. Performance
- Parallel processing option for file analysis
- Better caching strategy
- Streaming responses for large outputs

---

## Implementation Priority

1. **Fix import path** (blocks usability)
2. **Add requirements.txt** (blocks setup)
3. **Fix model inconsistency** (documentation accuracy)
4. **Add error handling** (stability)
5. **Extract common utilities** (maintainability)
6. **Add cost tracking** (user awareness)
7. **Improve documentation** (usability)

---

## Notes

- Consider creating a unified CLI entry point that lets users choose analyzer mode
- Evaluate if `rc1/` scripts should be deprecated in favor of `smart__.py`
- Consider integration with main project for hybrid analysis

