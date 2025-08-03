"""Data models for MCP Security Scanner."""

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class FindingSeverity(str, Enum):
    """Finding severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    WARNING = "warning"
    LOW = "low"
    INFO = "info"
    ERROR = "error"


# Alias for backwards compatibility
Severity = FindingSeverity


class FindingCategory(str, Enum):
    """Categories of security findings."""
    TYPOSQUATTING = "typosquatting"
    SEMANTIC_DRIFT = "semantic_drift"
    DEPENDENCY_VULN = "dependency_vulnerability"
    PROMPT_INJECTION = "prompt_injection"
    EXCESSIVE_PERMISSIONS = "excessive_permissions"
    NETWORK_ANOMALY = "network_anomaly"
    FILESYSTEM_ANOMALY = "filesystem_anomaly"
    SCHEMA_VALIDATION = "schema_validation"
    CONFIGURATION = "configuration"
    PERMISSIONS = "permissions"
    TOOL_CAPABILITY = "tool_capability"
    INTERNAL_ERROR = "internal_error"
    CODE_PATTERN = "code_pattern"
    VULNERABILITY = "vulnerability"
    INFORMATION = "information"


# Alias for backwards compatibility
FindingType = FindingCategory


class Finding(BaseModel):
    """Security finding model."""
    severity: FindingSeverity
    category: FindingCategory
    title: str
    description: str
    recommendation: Optional[str] = None
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    column_number: Optional[int] = None
    cwe_id: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class MCPTool(BaseModel):
    """MCP tool definition."""
    name: str
    description: str
    input_schema: Dict[str, Any]
    output_schema: Optional[Dict[str, Any]] = None


class MCPManifest(BaseModel):
    """MCP server manifest."""
    path: str
    name: str
    version: str
    description: str
    author: Optional[str] = None
    tools: List[MCPTool] = Field(default_factory=list)
    permissions: List[str] = Field(default_factory=list)
    repository: Optional[str] = None


class ScanResult(BaseModel):
    """Result from a scanner."""
    scanner_name: str
    passed: bool
    findings: List[Finding] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    
    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == FindingSeverity.CRITICAL)
    
    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == FindingSeverity.HIGH)
    
    @property
    def medium_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == FindingSeverity.MEDIUM)
    
    @property
    def warning_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == FindingSeverity.WARNING)
    
    @property
    def low_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == FindingSeverity.LOW)


class AnalysisResult(BaseModel):
    """Result from an analyzer."""
    analyzer_name: str
    passed: bool
    findings: List[Finding] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)