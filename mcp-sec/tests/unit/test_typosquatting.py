"""Unit tests for typosquatting detection."""

import pytest
from mcp_sec.analyzers.typosquatting import TyposquattingAnalyzer
from mcp_sec.models import MCPManifest, MCPTool, FindingSeverity


class TestTyposquattingAnalyzer:
    """Test typosquatting detection functionality."""
    
    @pytest.fixture
    def analyzer(self):
        """Create a typosquatting analyzer instance."""
        return TyposquattingAnalyzer()
    
    @pytest.fixture
    def known_servers(self):
        """Get known server names."""
        return ["openai-server", "github-server", "filesystem-server", "database-server"]
    
    @pytest.fixture
    def manifest_factory(self):
        """Factory for creating test manifests."""
        def _create_manifest(name: str, tools=None):
            return MCPManifest(
                path="/test/mcp.json",
                name=name,
                version="1.0.0",
                description="Test server",
                tools=tools or []
            )
        return _create_manifest
    
    def test_detect_typosquatting_server_names(self, analyzer, manifest_factory):
        """Test detection of typosquatted server names."""
        # Test various typosquatting techniques
        test_cases = [
            ("opneai-server", "openai-server", True),  # Character swap
            ("openai-sever", "openai-server", True),   # Character deletion
            ("github-serverr", "github-server", True),  # Character addition
            ("gihub-server", "github-server", True),    # Character deletion
            ("completely-different", "openai-server", False),  # No similarity
        ]
        
        for test_name, expected_match, should_detect in test_cases:
            manifest = manifest_factory(test_name)
            result = analyzer.analyze(manifest)
            
            if should_detect:
                assert len(result.findings) > 0
                finding = result.findings[0]
                assert "typosquatting" in finding.title.lower()
                assert expected_match in finding.description
                assert finding.severity == FindingSeverity.WARNING
            else:
                assert len(result.findings) == 0
    
    def test_homograph_detection(self, analyzer, manifest_factory):
        """Test detection of homograph attacks."""
        # Using Latin characters that look like ASCII
        test_cases = [
            ("оpenai-server", "openai-server"),  # Cyrillic 'о' instead of Latin 'o'
            ("github-ѕerver", "github-server"),   # Cyrillic 'ѕ' instead of Latin 's'
        ]
        
        for test_name, expected_match in test_cases:
            manifest = manifest_factory(test_name)
            result = analyzer.analyze(manifest)
            
            assert len(result.findings) > 0
            finding = result.findings[0]
            assert "homograph" in finding.title.lower() or "typosquatting" in finding.title.lower()
            assert finding.severity in [FindingSeverity.WARNING, FindingSeverity.HIGH]
    
    def test_tool_name_typosquatting(self, analyzer, manifest_factory):
        """Test detection of typosquatted tool names."""
        tools = [
            MCPTool(
                name="execute_comand",  # Typo of "execute_command"
                description="Execute commands",
                input_schema={"type": "object"}
            ),
            MCPTool(
                name="read_flie",  # Typo of "read_file"
                description="Read files",
                input_schema={"type": "object"}
            )
        ]
        
        manifest = manifest_factory("test-server", tools)
        result = analyzer.analyze(manifest)
        
        # Should detect typosquatting in tool names
        tool_findings = [f for f in result.findings if "tool" in f.description.lower()]
        assert len(tool_findings) > 0
    
    def test_levenshtein_distance(self, analyzer):
        """Test Levenshtein distance calculation."""
        test_cases = [
            ("hello", "hello", 0),
            ("hello", "helo", 1),
            ("hello", "jello", 1),
            ("hello", "helol", 2),  # Transposition requires 2 edits
            ("hello", "world", 4),
        ]
        
        for s1, s2, expected_distance in test_cases:
            distance = analyzer._levenshtein_distance(s1, s2)
            assert distance == expected_distance
    
    def test_dice_coefficient(self, analyzer):
        """Test Dice coefficient calculation."""
        test_cases = [
            ("hello", "hello", 1.0),
            ("hello", "helo", 0.8),  # 4 common bigrams out of 5 total
            ("hello", "world", 0.0),  # No common bigrams
            ("test", "testing", 0.667), # 3 common bigrams out of 9 total
        ]
        
        for s1, s2, expected_coef in test_cases:
            coef = analyzer._dice_coefficient(s1, s2)
            assert abs(coef - expected_coef) < 0.1  # Allow small floating point differences
    
    def test_keyboard_distance(self, analyzer):
        """Test keyboard distance calculation."""
        test_cases = [
            ("q", "w", True),   # Adjacent keys
            ("a", "s", True),   # Adjacent keys
            ("q", "p", False),  # Not adjacent
            ("z", "m", False),  # Not adjacent
        ]
        
        for char1, char2, expected_adjacent in test_cases:
            is_adjacent = analyzer._keyboard_distance(char1, char2) == 1
            assert is_adjacent == expected_adjacent
    
    def test_visual_similarity(self, analyzer):
        """Test visual similarity detection."""
        similar_pairs = [
            ("l", "1"),  # Lowercase L and one
            ("O", "0"),  # Uppercase O and zero
            ("rn", "m"), # rn looks like m
            ("vv", "w"), # Two v's look like w
        ]
        
        for s1, s2 in similar_pairs:
            similarity = analyzer._visual_similarity(s1, s2)
            assert similarity > 0.5  # Should be considered similar
    
    def test_confidence_scoring(self, analyzer, manifest_factory):
        """Test confidence scoring for typosquatting detection."""
        # Very similar name should have high confidence
        manifest = manifest_factory("openai-servr")  # One character typo
        result = analyzer.analyze(manifest)
        
        assert len(result.findings) > 0
        metadata = result.findings[0].metadata
        assert "confidence" in metadata
        assert metadata["confidence"] > 0.7  # High confidence
        
        # Less similar name should have lower confidence
        manifest = manifest_factory("opnai-srvr")  # Multiple typos
        result = analyzer.analyze(manifest)
        
        if len(result.findings) > 0:
            metadata = result.findings[0].metadata
            assert metadata["confidence"] < 0.7  # Lower confidence