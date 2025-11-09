#!/usr/bin/env python3
"""
Review State Manager for maintaining context across review sessions.
Enables resuming reviews and providing context for Cursor/Claude.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class ReviewCheckpoint:
    """Represents a checkpoint in the review process."""
    stage: str  # "prioritization", "deep_dive", "synthesis", etc.
    timestamp: str
    data: Dict[str, Any]  # Stage-specific data
    files_analyzed: List[str] = field(default_factory=list)
    findings_count: int = 0


@dataclass
class ReviewState:
    """Complete state of a code review session."""
    review_id: str
    repo_path: str
    dir_fingerprint: str
    question: str
    status: str  # "in_progress", "completed", "paused"
    created_at: str
    updated_at: str
    checkpoints: List[ReviewCheckpoint] = field(default_factory=list)
    files_analyzed: List[str] = field(default_factory=list)
    findings: List[Dict[str, Any]] = field(default_factory=list)
    synthesis: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


class ReviewStateManager:
    """Manages review state persistence and resumption."""
    
    def __init__(self, cache_dir: str):
        self.cache_dir = Path(cache_dir)
        self.reviews_dir = self.cache_dir / "reviews"
        self.reviews_dir.mkdir(parents=True, exist_ok=True)
    
    def compute_dir_fingerprint(self, repo_path: Path) -> str:
        """
        Compute a deterministic hash of the directory structure.
        Uses file paths, sizes, and modification times.
        """
        repo = Path(repo_path).resolve()
        if not repo.is_dir():
            raise ValueError(f"Repository path '{repo_path}' is not a directory")
        
        file_info = []
        for file_path in sorted(repo.rglob("*")):
            if not file_path.is_file():
                continue
            try:
                stat = file_path.stat()
                relative = file_path.relative_to(repo)
                file_info.append(f"{relative}:{stat.st_size}:{stat.st_mtime}")
            except (OSError, PermissionError):
                continue
        
        content = "\n".join(file_info)
        return hashlib.sha256(content.encode("utf-8")).hexdigest()[:16]
    
    def generate_review_id(self, repo_path: str, question: str) -> str:
        """Generate a unique review ID based on repo path and question."""
        content = f"{repo_path}|{question}|{datetime.now(timezone.utc).isoformat()}"
        return hashlib.sha256(content.encode("utf-8")).hexdigest()[:12]
    
    def find_matching_review(self, repo_path: str, dir_fingerprint: str) -> Optional[str]:
        """
        Find an existing review that matches the directory fingerprint.
        Returns review_id if found, None otherwise.
        """
        if not self.reviews_dir.exists():
            return None
        
        for review_file in self.reviews_dir.glob("*.json"):
            if review_file.name.startswith("_"):  # Skip context files
                continue
            try:
                state = self.load_review(review_file.stem)
                if (state.repo_path == repo_path and 
                    state.dir_fingerprint == dir_fingerprint and
                    state.status == "in_progress"):
                    return state.review_id
            except Exception:
                continue
        return None
    
    def create_review(
        self, repo_path: str, question: str, dir_fingerprint: Optional[str] = None
    ) -> ReviewState:
        """Create a new review state."""
        if dir_fingerprint is None:
            dir_fingerprint = self.compute_dir_fingerprint(Path(repo_path))
        
        review_id = self.generate_review_id(repo_path, question)
        now = datetime.now(timezone.utc).isoformat()
        
        state = ReviewState(
            review_id=review_id,
            repo_path=repo_path,
            dir_fingerprint=dir_fingerprint,
            question=question,
            status="in_progress",
            created_at=now,
            updated_at=now,
        )
        
        self.save_review(state)
        return state
    
    def save_review(self, state: ReviewState) -> None:
        """Save review state to disk."""
        state.updated_at = datetime.now(timezone.utc).isoformat()
        
        # Save structured JSON
        state_file = self.reviews_dir / f"{state.review_id}.json"
        state_dict = {
            "review_id": state.review_id,
            "repo_path": state.repo_path,
            "dir_fingerprint": state.dir_fingerprint,
            "question": state.question,
            "status": state.status,
            "created_at": state.created_at,
            "updated_at": state.updated_at,
            "checkpoints": [asdict(cp) for cp in state.checkpoints],
            "files_analyzed": state.files_analyzed,
            "findings": state.findings,
            "synthesis": state.synthesis,
            "metadata": state.metadata,
        }
        state_file.write_text(json.dumps(state_dict, indent=2), encoding="utf-8")
        
        # Generate human-readable context file for Cursor/Claude
        self._generate_context_file(state)
    
    def load_review(self, review_id: str) -> ReviewState:
        """Load review state from disk."""
        state_file = self.reviews_dir / f"{review_id}.json"
        if not state_file.exists():
            raise FileNotFoundError(f"Review {review_id} not found")
        
        data = json.loads(state_file.read_text(encoding="utf-8"))
        
        checkpoints = [
            ReviewCheckpoint(**cp_data) for cp_data in data.get("checkpoints", [])
        ]
        
        return ReviewState(
            review_id=data["review_id"],
            repo_path=data["repo_path"],
            dir_fingerprint=data["dir_fingerprint"],
            question=data["question"],
            status=data["status"],
            created_at=data["created_at"],
            updated_at=data["updated_at"],
            checkpoints=checkpoints,
            files_analyzed=data.get("files_analyzed", []),
            findings=data.get("findings", []),
            synthesis=data.get("synthesis"),
            metadata=data.get("metadata", {}),
        )
    
    def add_checkpoint(
        self, review_id: str, stage: str, data: Dict[str, Any], 
        files_analyzed: Optional[List[str]] = None, findings_count: int = 0
    ) -> None:
        """Add a checkpoint to the review."""
        state = self.load_review(review_id)
        
        checkpoint = ReviewCheckpoint(
            stage=stage,
            timestamp=datetime.now(timezone.utc).isoformat(),
            data=data,
            files_analyzed=files_analyzed or [],
            findings_count=findings_count,
        )
        
        state.checkpoints.append(checkpoint)
        self.save_review(state)
    
    def update_findings(self, review_id: str, findings: List[Any]) -> None:
        """Update findings in the review state.
        
        Args:
            review_id: Review ID
            findings: List of Finding objects (dataclass) or dicts
        """
        state = self.load_review(review_id)
        # Convert Finding dataclass objects to dicts
        findings_dicts = []
        for f in findings:
            if hasattr(f, '__dataclass_fields__'):  # It's a dataclass
                findings_dicts.append(asdict(f))
            elif isinstance(f, dict):
                findings_dicts.append(f)
            else:
                # Fallback: try to convert to dict
                findings_dicts.append(asdict(f) if hasattr(f, '__dict__') else {})
        state.findings = findings_dicts
        self.save_review(state)
    
    def update_synthesis(self, review_id: str, synthesis: str) -> None:
        """Update synthesis in the review state."""
        state = self.load_review(review_id)
        state.synthesis = synthesis
        self.save_review(state)
    
    def mark_completed(self, review_id: str) -> None:
        """Mark review as completed."""
        state = self.load_review(review_id)
        state.status = "completed"
        self.save_review(state)
    
    def list_reviews(self, status: Optional[str] = None) -> List[ReviewState]:
        """List all reviews, optionally filtered by status."""
        if not self.reviews_dir.exists():
            return []
        
        reviews = []
        for review_file in self.reviews_dir.glob("*.json"):
            if review_file.name.startswith("_"):
                continue
            try:
                state = self.load_review(review_file.stem)
                if status is None or state.status == status:
                    reviews.append(state)
            except Exception:
                continue
        
        # Sort by updated_at, most recent first
        reviews.sort(key=lambda r: r.updated_at, reverse=True)
        return reviews
    
    def _generate_context_file(self, state: ReviewState) -> None:
        """Generate human-readable context file for Cursor/Claude."""
        context_file = self.reviews_dir / f"_{state.review_id}_context.md"
        
        lines = [
            f"# Review Context: {state.review_id}",
            "",
            f"**Repository:** `{state.repo_path}`",
            f"**Question:** {state.question}",
            f"**Status:** {state.status}",
            f"**Created:** {state.created_at}",
            f"**Last Updated:** {state.updated_at}",
            f"**Directory Fingerprint:** `{state.dir_fingerprint}`",
            "",
            "---",
            "",
            "## Review Progress",
            "",
        ]
        
        if state.checkpoints:
            lines.append("### Checkpoints")
            for cp in state.checkpoints:
                lines.append(f"- **{cp.stage}** ({cp.timestamp})")
                if cp.files_analyzed:
                    lines.append(f"  - Files analyzed: {len(cp.files_analyzed)}")
                if cp.findings_count > 0:
                    lines.append(f"  - Findings: {cp.findings_count}")
            lines.append("")
        
        if state.files_analyzed:
            lines.extend([
                "## Files Analyzed",
                "",
                f"Total: {len(state.files_analyzed)}",
                "",
            ])
            for file_path in state.files_analyzed[:20]:  # Limit to first 20
                lines.append(f"- `{file_path}`")
            if len(state.files_analyzed) > 20:
                lines.append(f"- ... and {len(state.files_analyzed) - 20} more")
            lines.append("")
        
        if state.findings:
            lines.extend([
                "## Findings Summary",
                "",
                f"Total findings: {len(state.findings)}",
                "",
            ])
            # Group by impact
            impact_counts = {}
            for finding in state.findings:
                impact = finding.get("impact", "UNKNOWN")
                impact_counts[impact] = impact_counts.get(impact, 0) + 1
            
            for impact in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
                if impact in impact_counts:
                    lines.append(f"- **{impact}**: {impact_counts[impact]}")
            lines.append("")
        
        if state.synthesis:
            lines.extend([
                "## Synthesis",
                "",
                state.synthesis,
                "",
            ])
        
        lines.extend([
            "---",
            "",
            "## Next Steps",
            "",
            "To resume this review:",
            f"```bash",
            f"python3 smart__.py {state.repo_path} \"{state.question}\" --resume-review {state.review_id}",
            "```",
            "",
        ])
        
        context_file.write_text("\n".join(lines), encoding="utf-8")

