#!/usr/bin/env python3
"""
Common utilities shared across beta analyzers.
Reduces code duplication and provides consistent behavior.
"""

from __future__ import annotations

import json
import logging
import os
import re
import sys
from pathlib import Path
from typing import Optional

# Shared constants
SKIP_DIRS = {".git", "node_modules", "__pycache__", "vendor", "build", "dist"}
CODE_EXTS = {".py", ".go", ".java", ".js", ".ts", ".php", ".rb", ".jsx", ".tsx"}
YAML_EXTS = {".yaml", ".yml"}
HELM_EXTS = {".tpl", ".gotmpl"}

# JSON parsing regex (matches code fences)
_CODE_FENCE_RE = re.compile(r"^```(?:json)?\s*|\s*```$", re.MULTILINE)


def get_api_key() -> str:
    """Retrieves the Claude API key from environment variable."""
    try:
        api_key = os.environ["CLAUDE_API_KEY"]
    except KeyError:
        logging.error("CLAUDE_API_KEY environment variable must be set")
        sys.exit(1)
    return api_key


def parse_json_response(response_text: str, max_size: int = 1_000_000) -> Optional[dict]:
    """
    Safely parses a JSON object from API response text.
    Handles code fences and extracts JSON from unstructured text.
    
    Args:
        response_text: Raw API response text
        max_size: Maximum response size in bytes to prevent memory exhaustion
    
    Returns:
        Parsed JSON dict or None if parsing fails
    """
    if not response_text:
        return None
    
    if len(response_text) > max_size:
        logging.warning(f"Response too large: {len(response_text)} bytes, max {max_size}")
        return None
    
    # Remove markdown code fences if present
    cleaned = _CODE_FENCE_RE.sub("", response_text).strip()
    
    # Find JSON object boundaries
    start = cleaned.find("{")
    end = cleaned.rfind("}")
    
    if start != -1 and end != -1 and end > start:
        try:
            return json.loads(cleaned[start : end + 1])
        except json.JSONDecodeError:
            # Try with regex for nested objects
            match = re.search(r'\{.*\}', cleaned, re.DOTALL)
            if match:
                try:
                    return json.loads(match.group(0))
                except json.JSONDecodeError:
                    return None
            return None
    return None


def scan_repo_files(
    repo_path: str | Path,
    include_yaml: bool = False,
    include_helm: bool = False,
    max_file_bytes: int = 500_000,
    max_files: int = 400,
    skip_dirs: Optional[set[str]] = None,
) -> list[Path]:
    """
    Scans a repository for code files suitable for analysis.
    
    Args:
        repo_path: Path to repository root
        include_yaml: Whether to include YAML files
        include_helm: Whether to include Helm template files
        max_file_bytes: Maximum file size to analyze
        max_files: Maximum number of files to return
        skip_dirs: Additional directories to skip (merged with default SKIP_DIRS)
    
    Returns:
        Sorted list of file paths to analyze
    """
    repo = Path(repo_path)
    if not repo.is_dir():
        raise ValueError(f"Repository path '{repo_path}' is not a directory")
    
    allowed_exts = set(CODE_EXTS)
    if include_yaml:
        allowed_exts |= YAML_EXTS
    if include_helm:
        allowed_exts |= HELM_EXTS
    
    skip_patterns = SKIP_DIRS | (skip_dirs or set())
    
    results: list[Path] = []
    for file_path in repo.rglob("*"):
        if len(results) >= max_files:
            break
        
        if not file_path.is_file():
            continue
        
        # Skip excluded directories
        if any(skip in file_path.parts for skip in skip_patterns):
            continue
        
        # Check extension
        if file_path.suffix.lower() not in allowed_exts:
            continue
        
        # Check file size with proper error handling
        try:
            file_stat = file_path.stat()
            if file_stat.st_size > max_file_bytes:
                continue
        except (OSError, PermissionError):
            continue
        
        # Use resolved paths for canonical representation
        results.append(file_path.resolve())
    
    # Sort by extension and full path for consistent ordering
    return sorted(results, key=lambda p: (p.suffix, str(p).lower()))


def validate_repo_path(path: str | Path) -> Path:
    """Validates that a repository path exists and is a directory."""
    repo_path = Path(path).resolve()
    if not repo_path.exists():
        raise ValueError(f"Repository path does not exist: {path}")
    if not repo_path.is_dir():
        raise ValueError(f"Repository path is not a directory: {path}")
    return repo_path


def estimate_api_cost(input_tokens: int, output_tokens: int, model: str = "haiku") -> float:
    """
    Estimates API cost based on token usage.
    
    Pricing (as of 2024):
    - Haiku: $0.25/$1.25 per 1M input/output tokens
    - Sonnet: $3/$15 per 1M input/output tokens
    
    Args:
        input_tokens: Number of input tokens
        output_tokens: Number of output tokens
        model: Model name ('haiku' or 'sonnet')
    
    Returns:
        Estimated cost in USD
    """
    pricing = {
        "haiku": (0.25 / 1_000_000, 1.25 / 1_000_000),
        "sonnet": (3.0 / 1_000_000, 15.0 / 1_000_000),
    }
    
    input_price, output_price = pricing.get(model.lower(), pricing["haiku"])
    return (input_tokens * input_price) + (output_tokens * output_price)

