"""Typosquatting detection for MCP servers."""

from typing import List, Dict, Any, Set, Tuple
from mcp_sec.models import AnalysisResult, Finding, FindingSeverity, FindingCategory, MCPManifest


class TyposquattingAnalyzer:
    """Analyzer for detecting typosquatting attempts."""
    
    # Known legitimate MCP server names
    KNOWN_SERVERS = [
        "openai-server", "anthropic-server", "github-server", 
        "filesystem-server", "database-server", "api-server",
        "web-server", "slack-server", "discord-server"
    ]
    
    # Common tool names to check
    COMMON_TOOL_NAMES = [
        "execute_command", "read_file", "write_file", "list_files",
        "query_database", "send_message", "make_request"
    ]
    
    # Keyboard layout for distance calculation
    KEYBOARD_LAYOUT = {
        'q': (0, 0), 'w': (0, 1), 'e': (0, 2), 'r': (0, 3), 't': (0, 4),
        'y': (0, 5), 'u': (0, 6), 'i': (0, 7), 'o': (0, 8), 'p': (0, 9),
        'a': (1, 0), 's': (1, 1), 'd': (1, 2), 'f': (1, 3), 'g': (1, 4),
        'h': (1, 5), 'j': (1, 6), 'k': (1, 7), 'l': (1, 8),
        'z': (2, 0), 'x': (2, 1), 'c': (2, 2), 'v': (2, 3), 'b': (2, 4),
        'n': (2, 5), 'm': (2, 6)
    }
    
    def analyze(self, manifest: MCPManifest) -> AnalysisResult:
        """Analyze manifest for typosquatting attempts."""
        findings = []
        
        # Check server name
        server_findings = self._check_server_name(manifest.name)
        findings.extend(server_findings)
        
        # Check tool names
        for tool in manifest.tools:
            tool_findings = self._check_tool_name(tool.name)
            findings.extend(tool_findings)
        
        return AnalysisResult(
            analyzer_name="typosquatting",
            passed=len(findings) == 0,
            findings=findings,
            metadata={
                "server_name": manifest.name,
                "tool_count": len(manifest.tools)
            }
        )
    
    def _check_server_name(self, name: str) -> List[Finding]:
        """Check if server name might be typosquatting."""
        findings = []
        name_lower = name.lower()
        
        for known in self.KNOWN_SERVERS:
            known_lower = known.lower()
            
            # Skip if exact match
            if name_lower == known_lower:
                continue
            
            # Calculate various similarity metrics
            lev_dist = self._levenshtein_distance(name_lower, known_lower)
            dice_coef = self._dice_coefficient(name_lower, known_lower)
            
            # High confidence typosquatting (1-2 character difference)
            if 0 < lev_dist <= 2:
                confidence = 0.9 if lev_dist == 1 else 0.7
                findings.append(Finding(
                    severity=FindingSeverity.WARNING,
                    category=FindingCategory.TYPOSQUATTING,
                    title="Possible typosquatting detected",
                    description=f"Server name '{name}' is very similar to known server '{known}' (edit distance: {lev_dist})",
                    recommendation=f"If this is unintentional, consider using '{known}' instead",
                    metadata={
                        "similar_to": known,
                        "levenshtein_distance": lev_dist,
                        "confidence": confidence
                    }
                ))
            
            # Medium confidence based on Dice coefficient
            elif dice_coef > 0.7:
                findings.append(Finding(
                    severity=FindingSeverity.WARNING,
                    category=FindingCategory.TYPOSQUATTING,
                    title="Name similarity detected", 
                    description=f"Server name '{name}' has high character similarity to '{known}' (Dice coefficient: {dice_coef:.2f})",
                    recommendation="Consider using a more distinct name to avoid confusion",
                    metadata={
                        "similar_to": known,
                        "dice_coefficient": dice_coef,
                        "confidence": dice_coef
                    }
                ))
        
        # Check for homograph attacks
        homograph_findings = self._check_homographs(name)
        findings.extend(homograph_findings)
        
        return findings
    
    def _check_tool_name(self, name: str) -> List[Finding]:
        """Check if tool name might be typosquatting."""
        findings = []
        name_lower = name.lower()
        
        for common in self.COMMON_TOOL_NAMES:
            common_lower = common.lower()
            
            if name_lower == common_lower:
                continue
            
            lev_dist = self._levenshtein_distance(name_lower, common_lower)
            
            if 0 < lev_dist <= 2:
                findings.append(Finding(
                    severity=FindingSeverity.INFO,
                    category=FindingCategory.TYPOSQUATTING,
                    title="Possible tool name typo",
                    description=f"Tool name '{name}' is similar to common name '{common}' (edit distance: {lev_dist})",
                    recommendation=f"If this tool performs similar functionality, consider using the standard name '{common}'",
                    metadata={
                        "similar_to": common,
                        "levenshtein_distance": lev_dist
                    }
                ))
        
        return findings
    
    def _check_homographs(self, name: str) -> List[Finding]:
        """Check for homograph attacks using similar-looking characters."""
        findings = []
        
        # Common homograph substitutions
        homographs = {
            'o': ['0', 'о', 'ο'],  # Latin o, zero, Cyrillic o, Greek omicron
            'l': ['1', 'I', '|', 'ı'],  # Lowercase L, one, uppercase i, pipe, dotless i
            'e': ['е', 'ε'],  # Latin e, Cyrillic e, Greek epsilon
            'a': ['а', '@', 'α'],  # Latin a, Cyrillic a, at sign, Greek alpha
            'i': ['і', '1', '|'],  # Latin i, Ukrainian i, one, pipe
            's': ['ѕ', '$', '5'],  # Latin s, Cyrillic dze, dollar, five
            'c': ['с', 'ϲ'],  # Latin c, Cyrillic s, Greek lunate sigma
            'p': ['р', 'ρ'],  # Latin p, Cyrillic r, Greek rho
            'x': ['х', 'χ'],  # Latin x, Cyrillic kh, Greek chi
            'y': ['у', 'ү'],  # Latin y, Cyrillic u, Cyrillic ue
        }
        
        suspicious_chars = []
        for i, char in enumerate(name):
            for latin, lookalikes in homographs.items():
                if char in lookalikes:
                    suspicious_chars.append((i, char, latin))
        
        if suspicious_chars:
            findings.append(Finding(
                severity=FindingSeverity.HIGH,
                category=FindingCategory.TYPOSQUATTING,
                title="Possible homograph attack detected",
                description=f"Name '{name}' contains non-Latin characters that look similar to Latin letters: {[(c[1], c[2]) for c in suspicious_chars]}",
                recommendation="Use only standard ASCII characters in server names",
                metadata={
                    "suspicious_characters": suspicious_chars,
                    "name": name
                }
            ))
        
        return findings
    
    def _levenshtein_distance(self, s1: str, s2: str) -> int:
        """Calculate Levenshtein distance between two strings."""
        if len(s1) < len(s2):
            return self._levenshtein_distance(s2, s1)
        
        if len(s2) == 0:
            return len(s1)
        
        previous_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                # j+1 instead of j since previous_row and current_row are one character longer than s2
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row
        
        return previous_row[-1]
    
    def _dice_coefficient(self, s1: str, s2: str) -> float:
        """Calculate Dice coefficient between two strings."""
        if not s1 or not s2:
            return 0.0
        
        # Convert to bigrams
        bigrams1 = set(s1[i:i+2] for i in range(len(s1)-1))
        bigrams2 = set(s2[i:i+2] for i in range(len(s2)-1))
        
        if not bigrams1 or not bigrams2:
            return 0.0
        
        intersection = len(bigrams1 & bigrams2)
        return 2.0 * intersection / (len(bigrams1) + len(bigrams2))
    
    def _keyboard_distance(self, c1: str, c2: str) -> int:
        """Calculate keyboard distance between two characters."""
        c1 = c1.lower()
        c2 = c2.lower()
        
        if c1 not in self.KEYBOARD_LAYOUT or c2 not in self.KEYBOARD_LAYOUT:
            return 999  # Large distance for unknown characters
        
        pos1 = self.KEYBOARD_LAYOUT[c1]
        pos2 = self.KEYBOARD_LAYOUT[c2]
        
        # Manhattan distance
        return abs(pos1[0] - pos2[0]) + abs(pos1[1] - pos2[1])
    
    def _visual_similarity(self, s1: str, s2: str) -> float:
        """Calculate visual similarity between strings."""
        # Simple implementation - checks for visually similar character pairs
        similar_pairs = [
            ('l', '1'), ('O', '0'), ('rn', 'm'), ('vv', 'w')
        ]
        
        # Check each combination
        s1_lower = s1.lower()
        s2_lower = s2.lower()
        
        # Direct check for visual similarity
        for pair1, pair2 in similar_pairs:
            # Check both directions
            if (s1_lower == pair1 and s2_lower == pair2) or (s1_lower == pair2 and s2_lower == pair1):
                return 1.0
            if (s1 == pair1 and s2 == pair2) or (s1 == pair2 and s2 == pair1):
                return 1.0
        
        # Check with replacements
        s1_norm = s1
        s2_norm = s2
        for pair1, pair2 in similar_pairs:
            # Replace in both directions
            s1_test = s1.replace(pair1, pair2).replace(pair2, pair1)
            s2_test = s2.replace(pair1, pair2).replace(pair2, pair1)
            if s1_test == s2 or s1 == s2_test:
                return 1.0
        
        # Use Dice coefficient as fallback
        return self._dice_coefficient(s1, s2)