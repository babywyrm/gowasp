#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Centralized prompt builders for SmartAnalyzer.
Keeping prompts separate makes the core pipeline lighter and easier to maintain.
"""

from __future__ import annotations
from pathlib import Path
from typing import List


class PromptFactory:
    """Generates dynamic prompts for each stage of the analysis."""

    @staticmethod
    def prioritization(all_files: List[Path], question: str) -> str:
        import json as _json
        filenames = [f.name for f in all_files]
        return f"""You are a lead software architect. Based on the user's question, identify the most critical files to analyze from the list below.

User Question: "{question}"

File List:
{_json.dumps(filenames, indent=2)}

Return a JSON object with a single key "prioritized_files" containing a list of the top 15 most relevant filenames. Your response must contain ONLY the JSON object.
Example: {{"prioritized_files": ["Login.java", "UserService.java", "ApiAction.java"]}}"""

    @staticmethod
    def deep_dive(file_path: Path, content: str, question: str) -> str:
        """Generic code prompt (Go/Java/Python/JS/etc.)."""
        return f"""You are an expert code analyst. Analyze the following code in the context of the user's question.
FILE: {file_path}
QUESTION: {question}

Provide a concise analysis in this exact JSON format. Your entire response must be ONLY the JSON object.
{{
  "relevance": "HIGH|MEDIUM|LOW|NONE",
  "insights": [
    {{
      "finding": "Description of the finding.",
      "line_number": 45,
      "recommendation": "Specific, actionable recommendation."
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

Treat this as either a Kubernetes manifest or a Helm values file. If multiple YAML docs exist (---), analyze each briefly. Identify security misconfigurations, upgrade risks, and best-practice deviations (e.g., missing resources, securityContext, RBAC risks, hostPath, NodePort, privileged, runAsRoot, emptyDir for data, etc.).

Provide a concise analysis in THIS EXACT JSON format. Respond ONLY with the JSON object.
{{
  "relevance": "HIGH|MEDIUM|LOW|NONE",
  "detected_type": "k8s-manifest|helm-values|unknown",
  "insights": [
    {{
      "finding": "Description of the issue, misconfig, or notable behavior (security, reliability, or best practice).",
      "line_number": 1,
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

Consider Go templating, functions (include, tpl, toYaml), values usage, and Kubernetes schema validity after rendering. Point out anti-patterns (hard-coded images/tags, missing resources, insecure securityContext, cluster-admin RBAC, NodePort exposure, hostPath, privileged, etc.). Mention Helm upgrade pitfalls (immutable fields, StatefulSet changes, selector/template hash changes).

Provide a concise analysis in THIS EXACT JSON format. Respond ONLY with the JSON object.
{{
  "relevance": "HIGH|MEDIUM|LOW|NONE",
  "detected_type": "helm-template",
  "insights": [
    {{
      "finding": "Specific template or values misuse, security issue, or upgrade pitfall.",
      "line_number": 1,
      "recommendation": "Action to fix or validate (e.g., schema check, value default, securityContext hardening)."
    }}
  ]
}}
HELM TEMPLATE TO ANALYZE:
{content}"""

    @staticmethod
    def synthesis(all_findings: list, question: str) -> str:
        """Generate the executive summary based on findings and question."""
        from pathlib import Path as _Path
        condensed_findings = [f"- {f.finding} (in {_Path(f.file_path).name})" for f in all_findings]

        q_lower = question.lower()
        if any(kw in q_lower for kw in ("security", "vulnerability", "threat", "exploit")):
            synthesis_goal = """1.  **Executive Summary:** A brief, high-level overview of the codebase's security posture.
2.  **Top Threat Vectors:** Identify the 3-5 most critical, overarching vulnerability patterns.
3.  **Strategic Remediation Plan:** Provide a prioritized, actionable plan to address these key patterns."""
        elif any(kw in q_lower for kw in ("performance", "speed", "latency", "bottleneck")):
            synthesis_goal = """1.  **Performance Profile:** A brief, high-level overview of the codebase's likely performance characteristics.
2.  **Key Bottlenecks:** Identify the 3-5 most critical, overarching performance anti-patterns.
3.  **Optimization Strategy:** Provide a prioritized, actionable plan to address these key bottlenecks."""
        else:
            synthesis_goal = """1.  **Architectural Overview:** A brief, high-level summary of the codebase's design and quality.
2.  **Key Code Smells / Patterns:** Identify the 3-5 most critical, overarching design or maintenance issues.
3.  **Strategic Refactoring Plan:** Provide a prioritized, actionable plan to improve the codebase's structure and maintainability."""

        return f"""You are a principal software architect providing an executive summary. Based on the user's original question and the list of raw findings from a codebase scan, generate a high-level report in Markdown with the following sections:
{synthesis_goal}

Original Question: "{question}"
Raw Findings:
{chr(10).join(condensed_findings)}"""

    @staticmethod
    def payload_generation(finding, code_snippet: str) -> str:
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
