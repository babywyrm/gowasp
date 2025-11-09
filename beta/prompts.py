#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Centralized prompt builders for SmartAnalyzer.
Keeping prompts separate makes the core pipeline lighter and easier to maintain.
"""

from __future__ import annotations
import json as _json
import os
from pathlib import Path
from typing import Any, Dict, List


class PromptFactory:
    """Generates dynamic prompts for each stage of the analysis."""

    @staticmethod
    def prioritization(all_files: List[Path], question: str, limit: int) -> str:
        filenames = [f.name for f in all_files]
        return f"""You are a lead software architect. Your task is to identify the most critical files to analyze to answer the user's question.

User Question: "{question}"

File List:
{_json.dumps(filenames, indent=2)}

Return a JSON object with a single key "prioritized_files". This key should contain a list of objects, where each object has a "file_name" and a "reason" explaining its relevance. Limit the list to the top {limit} most relevant files. Your response must contain ONLY the JSON object.
Example:
{{
  "prioritized_files": [
    {{
      "file_name": "UserService.java",
      "reason": "This file likely handles user creation and authentication, which is central to the user's security question."
    }},
    {{
      "file_name": "JwtUtil.java",
      "reason": "This file probably manages JWT token generation and validation, a critical component of authorization."
    }}
  ]
}}"""

    @staticmethod
    def deep_dive(file_path: Path, content: str, question: str) -> str:
        """Generic code prompt with enhanced AppSec requirements."""
        return f"""You are a Principal Application Security Engineer. Your analysis must be meticulous, pragmatic, and map to industry standards. Analyze the following code in the context of the user's question.

FILE: {file_path}
QUESTION: {question}

Provide your analysis in this exact JSON format. Your entire response must be ONLY the JSON object.
{{
  "relevance": "HIGH|MEDIUM|LOW|NONE",
  "insights": [
    {{
      "finding": "A concise description of the specific security weakness.",
      "impact": "CRITICAL|HIGH|MEDIUM|LOW",
      "confidence": "HIGH|MEDIUM|LOW",
      "effort": "HIGH|MEDIUM|LOW",
      "line_number": 45,
      "cwe": "CWE-ID (e.g., 'CWE-89' for SQL Injection). If not applicable or unsure, use 'N/A'.",
      "recommendation": "A specific, actionable recommendation with a brief 'why'."
    }}
  ]
}}

CODE TO ANALYZE:
{content}"""

    @staticmethod
    def deep_dive_yaml(file_path: Path, content: str, question: str) -> str:
        """Analyze Kubernetes/values YAML with security & correctness hints."""
        return f"""You are a Kubernetes and DevSecOps expert. Analyze the following YAML file in the context of the user's question.
FILE: {file_path}
QUESTION: {question}

Treat this as either a Kubernetes manifest or a Helm values file. Identify security misconfigurations (e.g., missing resources, securityContext, RBAC risks, hostPath, privileged), upgrade risks, and best-practice deviations.

Provide a concise analysis in THIS EXACT JSON format. Respond ONLY with the JSON object.
{{
  "relevance": "HIGH|MEDIUM|LOW|NONE",
  "detected_type": "k8s-manifest|helm-values|unknown",
  "insights": [
    {{
      "finding": "Description of the issue, misconfig, or notable behavior.",
      "impact": "CRITICAL|HIGH|MEDIUM|LOW",
      "confidence": "HIGH|MEDIUM|LOW",
      "effort": "HIGH|MEDIUM|LOW",
      "line_number": 1,
      "cwe": "CWE-ID (e.g., 'CWE-22'). If not applicable or unsure, use 'N/A'.",
      "recommendation": "Specific, actionable remediation or validation."
    }}
  ]
}}
YAML TO ANALYZE:
{content}"""

    @staticmethod
    def deep_dive_helm(file_path: Path, content: str, question: str) -> str:
        """Analyze Helm templates (.tpl/.gotmpl or templates/*.yaml) safely."""
        return f"""You are a Helm + Kubernetes expert. Analyze this Helm template in the context of the user's question.
FILE: {file_path}
QUESTION: {question}

Consider Go templating, values usage, and Kubernetes schema validity. Point out anti-patterns (hard-coded images, insecure securityContext, cluster-admin RBAC, NodePort exposure, hostPath, etc.) and Helm upgrade pitfalls (immutable fields).

Provide a concise analysis in THIS EXACT JSON format. Respond ONLY with the JSON object.
{{
  "relevance": "HIGH|MEDIUM|LOW|NONE",
  "detected_type": "helm-template",
  "insights": [
    {{
      "finding": "Specific template or values misuse, security issue, or upgrade pitfall.",
      "impact": "CRITICAL|HIGH|MEDIUM|LOW",
      "confidence": "HIGH|MEDIUM|LOW",
      "effort": "HIGH|MEDIUM|LOW",
      "line_number": 1,
      "cwe": "CWE-ID. If not applicable or unsure, use 'N/A'.",
      "recommendation": "Action to fix or validate."
    }}
  ]
}}
HELM TEMPLATE TO ANALYZE:
{content}"""
    
    @staticmethod
    def annotation(finding: Any, code_content: str) -> str:
        """Generates a focused, annotated code snippet for a specific finding.
        
        Args:
            finding: Finding dataclass instance with file_path, line_number, finding, recommendation attributes
            code_content: Full content of the file containing the finding
        """
        return f"""You are a secure coding expert providing feedback in a code review. Your task is to create an annotated code snippet for a specific security finding.

SECURITY FINDING:
- File: {finding.file_path}
- Line: {finding.line_number}
- Description: {finding.finding}
- Recommendation: {finding.recommendation}

FULL CODE CONTENT:
{code_content}

INSTRUCTIONS:
1.  Extract a code snippet of 10-15 lines centered around the vulnerable line ({finding.line_number}).
2.  Add a comment directly above the vulnerable line: `// FLAW: [Brief summary of the flaw]`
3.  Add a comment block directly below the vulnerable line showing the corrected code: `// FIX: \n// [Corrected code line(s)]`

Provide your response in a single, clean JSON object with one key, "annotated_snippet". Do not include any text outside the JSON.
Example format:
{{
  "annotated_snippet": "public void insecureMethod(String userInput) {{\\n    // ... some code ...\\n    // FLAW: This line is vulnerable to SQL Injection.\\n    Statement stmt = conn.createStatement();\\n    ResultSet rs = stmt.executeQuery(\\"SELECT * FROM users WHERE name = '\" + userInput + \"'\\");\\n    // FIX:\\n    // PreparedStatement ps = conn.prepareStatement(\\"SELECT * FROM users WHERE name = ?\\");\\n    // ps.setString(1, userInput);\\n    // ResultSet rs = ps.executeQuery();\\n    // ... more code ...\\n}}"
}}"""

    @staticmethod
    def synthesis(all_findings: list, question: str) -> str:
        """Generate the executive summary based on findings and question."""
        from pathlib import Path as _Path
        condensed_findings = [
            f"- {finding.finding} (in {_Path(finding.file_path).name})" 
            for finding in all_findings
        ]
        
        synthesis_goal = """Your report must be in Markdown and contain the following three sections EXACTLY:

1.  **Executive Summary:** A one-paragraph, high-level overview for a non-technical manager. Explain the overall state of the codebase regarding the user's question and the primary business risk.

2.  **Key Patterns & Root Causes:** Instead of just listing findings, group them. Identify 2-4 overarching *patterns* or *root causes*. For example, "Systemic Lack of Input Validation" or "Inconsistent Error Handling." Explain why these patterns are problematic.

3.  **Prioritized Action Plan:** Provide a numbered list of concrete steps for the development team. Start with the highest-impact, lowest-effort items. Each step should reference the files involved."""

        return f"""You are a principal software architect tasked with creating a strategic report. Based on the user's original question and a list of raw findings, generate a high-level action plan.
{synthesis_goal}

Original Question: "{question}"

Raw Findings:
{os.linesep.join(condensed_findings)}"""

    @staticmethod
    def payload_generation(finding: Any, code_snippet: str) -> str:
        """Generate safe, educational payloads for verification and defense."""
        return f"""You are a security testing expert. For the following vulnerability finding, generate example payloads for both offensive verification (Red Team) and defensive testing (Blue Team). This is for authorized, educational purposes only.

VULNERABILITY CONTEXT:
File: {finding.file_path}
Line: {finding.line_number}
Finding: {finding.finding}

CODE SNIPPET:
{code_snippet}

TASK:
Provide your response in a single, clean JSON object with the following structure. Do not include any text outside the JSON.
{{
  "red_team_payload": {{
    "payload": "A simple, non-destructive payload to verify the flaw's existence.",
    "explanation": "A brief explanation of why this payload works for verification."
  }},
  "blue_team_payload": {{
    "payload": "A payload that can be used in a unit test or WAF rule to test the fix.",
    "explanation": "A brief explanation of how this payload helps test the defensive measure."
  }}
}}"""

    @staticmethod
    def code_improvement(file_path: Path, content: str, focus_areas: List[str]) -> str:
        """Generate suggestions to improve Python code quality."""
        focus_str = ", ".join(focus_areas) if focus_areas else "all aspects"
        
        return f"""You are a Python code quality expert. Analyze the following code and provide specific, actionable improvements focusing on: {focus_str}.

FILE: {file_path}

Your analysis should cover:
1. **Type Hints**: Add/improve type annotations (PEP 484)
2. **Readability**: Simplify complex logic, improve naming, reduce nesting
3. **Security**: Identify unsafe patterns (eval, exec, shell injection risks, etc.)
4. **Performance**: Suggest more efficient approaches
5. **Pythonic Code**: Use standard library better, follow PEP 8

Provide your response in this exact JSON format. Respond ONLY with the JSON object.
{{
  "overall_quality": "EXCELLENT|GOOD|FAIR|NEEDS_IMPROVEMENT",
  "improvements": [
    {{
      "category": "typing|readability|security|performance|pythonic",
      "line_number": 42,
      "current_code": "The problematic code snippet",
      "improved_code": "The improved version",
      "explanation": "Why this is better",
      "impact": "HIGH|MEDIUM|LOW"
    }}
  ],
  "summary": "Brief overall assessment and key recommendations"
}}

CODE TO ANALYZE:
{content}"""

    @staticmethod
    def full_code_optimization(
        file_path: Path, content: str, improvements: List[dict]
    ) -> str:
        """Generate a fully rewritten, optimized version of the code."""
        improvements_summary = "\n".join([
            f"- Line {imp.get('line_number', '?')}: {imp.get('finding', imp.get('explanation', 'N/A'))}"
            for imp in improvements
        ])
        
        return f"""You are a Python code optimization expert. Rewrite the following Python file incorporating ALL the improvements listed below.

FILE: {file_path}

IMPROVEMENTS TO APPLY:
{improvements_summary}

INSTRUCTIONS:
1. Rewrite the ENTIRE file with all improvements applied
2. Maintain all existing functionality
3. Preserve comments and docstrings (improve them if needed)
4. Ensure the code is production-ready
5. Return ONLY the improved Python code, no explanations

ORIGINAL CODE:
{content}

Return the complete, optimized Python file:"""
