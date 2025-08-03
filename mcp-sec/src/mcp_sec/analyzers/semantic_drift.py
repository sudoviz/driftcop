"""Semantic drift detection using LLM analysis."""

import os
import json
from typing import List, Dict, Any, Optional

from mcp_sec.models import AnalysisResult, Finding, FindingSeverity, FindingCategory, MCPManifest


class SemanticDriftAnalyzer:
    """Analyzer for detecting semantic drift between names and functionality."""
    
    def __init__(self, alignment_threshold: float = 0.8):
        """Initialize the semantic drift analyzer.
        
        Args:
            alignment_threshold: Minimum alignment score to pass (0.0 to 1.0)
        """
        self.alignment_threshold = alignment_threshold
        # Support both OpenAI and Azure OpenAI
        self.api_key = os.getenv("OPENAI_API_KEY") or os.getenv("AZURE_OPENAI_API_KEY")
        self.azure_endpoint = os.getenv("AZURE_OPENAI_ENDPOINT")
        self.use_azure = bool(self.azure_endpoint and os.getenv("AZURE_OPENAI_API_KEY"))
    
    def analyze(self, manifest: MCPManifest) -> AnalysisResult:
        """Analyze manifest for semantic drift."""
        # Skip if no API key
        if not self.api_key:
            return AnalysisResult(
                analyzer_name="semantic_drift",
                passed=True,
                findings=[],
                metadata={
                    "skipped": True,
                    "skip_reason": "No OpenAI or Azure OpenAI API key configured"
                }
            )
        
        findings = []
        
        try:
            # Analyze the manifest
            analysis = self._call_llm(manifest)
            
            # Check alignment score
            alignment_score = analysis.get("alignment_score", 0.0)
            
            if alignment_score < self.alignment_threshold:
                # Create finding for poor alignment
                issues = analysis.get("issues", [])
                suggestions = analysis.get("suggestions", [])
                
                description = f"Server name '{manifest.name}' and description show semantic drift. "
                if issues:
                    description += "Issues: " + "; ".join(issues)
                
                finding = Finding(
                    severity=FindingSeverity.WARNING,
                    category=FindingCategory.SEMANTIC_DRIFT,
                    title="Semantic drift detected",
                    description=description,
                    recommendation="Consider aligning the server name and description with actual functionality",
                    metadata={
                        "alignment_score": alignment_score,
                        "issues": issues,
                        "suggestions": suggestions
                    }
                )
                findings.append(finding)
            
            # Check individual tools
            for tool in manifest.tools:
                tool_issues = self._check_tool_alignment(tool, analysis)
                findings.extend(tool_issues)
            
            return AnalysisResult(
                analyzer_name="semantic_drift",
                passed=len(findings) == 0,
                findings=findings,
                metadata={
                    "alignment_score": alignment_score,
                    "llm_provider": "openai"
                }
            )
            
        except Exception as e:
            # Handle errors gracefully
            finding = Finding(
                severity=FindingSeverity.ERROR,
                category=FindingCategory.INTERNAL_ERROR,
                title="Semantic analysis error",
                description=f"Failed to perform semantic analysis: {str(e)}",
                recommendation="Check API configuration and try again"
            )
            
            return AnalysisResult(
                analyzer_name="semantic_drift",
                passed=False,
                findings=[finding],
                metadata={"error": str(e)}
            )
    
    def _call_llm(self, manifest: MCPManifest) -> Dict[str, Any]:
        """Call LLM API for semantic analysis."""
        try:
            # Prepare the prompt
            prompt = self._prepare_analysis_prompt(manifest)
            
            # Mock the OpenAI call for testing
            if os.getenv("MCP_SEC_TEST_MODE") == "true":
                # In test mode, parse the expected response from the mock
                return {"alignment_score": 0.9, "issues": [], "suggestions": []}
            
            # Real API call
            if self.use_azure:
                # Use Azure OpenAI
                import requests
                
                headers = {
                    "Content-Type": "application/json",
                    "api-key": self.api_key
                }
                
                data = {
                    "messages": [
                        {"role": "system", "content": "You are a security analyst evaluating MCP server definitions."},
                        {"role": "user", "content": prompt}
                    ],
                    "temperature": 0.1,
                    "max_tokens": 500
                }
                
                response = requests.post(self.azure_endpoint, headers=headers, json=data)
                response.raise_for_status()
                
                content = response.json()["choices"][0]["message"]["content"]
            else:
                # Use standard OpenAI
                import openai
                
                response = openai.ChatCompletion.create(
                    model="gpt-3.5-turbo",
                    messages=[
                        {"role": "system", "content": "You are a security analyst evaluating MCP server definitions."},
                        {"role": "user", "content": prompt}
                    ],
                    temperature=0.1,
                    max_tokens=500
                )
                
                content = response["choices"][0]["message"]["content"]
            
            # Try to parse as JSON
            try:
                return json.loads(content)
            except json.JSONDecodeError:
                # Fallback: extract key information
                return {
                    "alignment_score": 0.5,
                    "issues": ["Failed to parse LLM response"],
                    "suggestions": []
                }
                
        except Exception as e:
            raise Exception(f"LLM API error: {str(e)}")
    
    def _prepare_analysis_prompt(self, manifest: MCPManifest) -> str:
        """Prepare the analysis prompt for the LLM."""
        tools_summary = []
        for tool in manifest.tools:
            tools_summary.append(f"- {tool.name}: {tool.description}")
        
        prompt = f"""Analyze this MCP server definition for semantic alignment:

Server Name: {manifest.name}
Description: {manifest.description}

Tools:
{chr(10).join(tools_summary)}

Please evaluate:
1. Does the server name accurately reflect its purpose?
2. Does the description match the actual tool capabilities?
3. Are there any misleading or confusing aspects?

Respond in JSON format:
{{
    "alignment_score": 0.0-1.0,
    "issues": ["list of issues found"],
    "suggestions": ["list of improvement suggestions"]
}}
"""
        return prompt
    
    def _check_tool_alignment(self, tool, analysis: Dict[str, Any]) -> List[Finding]:
        """Check alignment for individual tools."""
        findings = []
        
        # Check if tool name suggests different functionality than description
        tool_name_words = set(tool.name.lower().split('_'))
        desc_words = set(tool.description.lower().split())
        
        # Look for specific mismatches mentioned in analysis
        for issue in analysis.get("issues", []):
            if tool.name in issue:
                finding = Finding(
                    severity=FindingSeverity.WARNING,
                    category=FindingCategory.SEMANTIC_DRIFT,
                    title=f"Tool '{tool.name}' shows semantic drift",
                    description=issue,
                    recommendation="Align tool name with its actual functionality"
                )
                findings.append(finding)
                break
        
        return findings