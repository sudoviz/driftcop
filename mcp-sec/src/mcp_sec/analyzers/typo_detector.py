"""Typosquatting detection for MCP server names."""

import uuid
from typing import List
import Levenshtein
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

from mcp_sec.models import Finding, FindingType, Severity
from mcp_sec.config import config


def check_server_name(name: str) -> List[Finding]:
    """Check if server name might be typosquatting a known server."""
    findings = []
    
    # Skip if name is in known list
    if name in config.known_servers:
        return findings
    
    # Check against each known server
    for known in config.known_servers:
        # Levenshtein distance check
        distance = Levenshtein.distance(name.lower(), known.lower())
        if 0 < distance <= 2:
            findings.append(Finding(
                id=str(uuid.uuid4()),
                type=FindingType.TYPOSQUATTING,
                severity=Severity.HIGH,
                title=f"Possible typosquatting of '{known}'",
                description=f"Server name '{name}' is very similar to known server '{known}' (edit distance: {distance})",
                cwe_id="CWE-601",
                fix_suggestion=f"If this is intentional, consider a more distinct name. If not, did you mean '{known}'?",
                metadata={"similar_to": known, "distance": distance}
            ))
        
        # Dice coefficient check
        dice_score = _dice_coefficient(name.lower(), known.lower())
        if dice_score > config.typo_similarity_threshold and name.lower() != known.lower():
            findings.append(Finding(
                id=str(uuid.uuid4()),
                type=FindingType.TYPOSQUATTING,
                severity=Severity.MEDIUM,
                title=f"Name similarity with '{known}'",
                description=f"Server name '{name}' has high similarity to '{known}' (Dice coefficient: {dice_score:.2f})",
                cwe_id="CWE-601",
                fix_suggestion="Consider a more distinct server name to avoid confusion",
                metadata={"similar_to": known, "dice_score": dice_score}
            ))
    
    # Check for homograph attacks (similar looking characters)
    homograph_findings = _check_homographs(name)
    findings.extend(homograph_findings)
    
    # Embedding-based similarity check
    if config.known_servers:
        embedding_findings = _check_embedding_similarity(name)
        findings.extend(embedding_findings)
    
    # Deduplicate findings for the same known server
    seen = set()
    unique_findings = []
    for finding in findings:
        key = (finding.metadata.get("similar_to"), finding.type)
        if key not in seen:
            seen.add(key)
            unique_findings.append(finding)
    
    return unique_findings


def _dice_coefficient(s1: str, s2: str) -> float:
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


def _check_homographs(name: str) -> List[Finding]:
    """Check for homograph attacks using similar-looking characters."""
    findings = []
    
    # Common homograph substitutions
    homographs = {
        'o': ['0', 'ο'],  # Latin o vs zero vs Greek omicron
        'l': ['1', 'I', '|'],  # Lowercase L vs one vs uppercase i vs pipe
        'e': ['е'],  # Latin e vs Cyrillic e
        'a': ['а', '@'],  # Latin a vs Cyrillic a vs at sign
        'i': ['і'],  # Latin i vs Ukrainian i
        'p': ['р'],  # Latin p vs Cyrillic r
        'c': ['с'],  # Latin c vs Cyrillic s
        'x': ['х'],  # Latin x vs Cyrillic kh
        'y': ['у'],  # Latin y vs Cyrillic u
    }
    
    suspicious_chars = []
    for char in name.lower():
        for original, substitutes in homographs.items():
            if char in substitutes:
                suspicious_chars.append((char, original))
    
    if suspicious_chars:
        findings.append(Finding(
            id=str(uuid.uuid4()),
            type=FindingType.TYPOSQUATTING,
            severity=Severity.HIGH,
            title="Possible homograph attack",
            description=f"Server name contains characters that look similar to Latin letters: {suspicious_chars}",
            cwe_id="CWE-601",
            fix_suggestion="Use only standard ASCII characters in server names",
            metadata={"suspicious_chars": suspicious_chars}
        ))
    
    return findings


def _check_embedding_similarity(name: str) -> List[Finding]:
    """Check semantic similarity using embeddings."""
    findings = []
    
    try:
        # Create TF-IDF vectors for character n-grams
        vectorizer = TfidfVectorizer(analyzer='char', ngram_range=(2, 3))
        
        all_names = config.known_servers + [name]
        tfidf_matrix = vectorizer.fit_transform(all_names)
        
        # Calculate cosine similarity
        name_vector = tfidf_matrix[-1]
        similarities = cosine_similarity(name_vector, tfidf_matrix[:-1])[0]
        
        # Check for high similarity
        for i, similarity in enumerate(similarities):
            if similarity > config.typo_similarity_threshold:
                known = config.known_servers[i]
                if name.lower() != known.lower():
                    findings.append(Finding(
                        id=str(uuid.uuid4()),
                        type=FindingType.TYPOSQUATTING,
                        severity=Severity.MEDIUM,
                        title=f"High character similarity with '{known}'",
                        description=f"Server name '{name}' has high character-level similarity to '{known}' (cosine: {similarity:.2f})",
                        cwe_id="CWE-601",
                        fix_suggestion="Choose a more distinctive server name",
                        metadata={"similar_to": known, "cosine_similarity": similarity}
                    ))
    
    except Exception:
        # If embedding check fails, continue without it
        pass
    
    return findings