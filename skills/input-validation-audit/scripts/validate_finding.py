#!/usr/bin/env python3
"""
Sub-agent validation framework for security findings.
Validates vulnerabilities and assigns confidence scores.
"""

import re
import json
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict


@dataclass
class Finding:
    """Security finding data structure."""
    vuln_type: str
    filepath: str
    line_number: int
    code_snippet: str
    input_source: Optional[str] = None
    data_flow: Optional[List[Dict]] = None
    confidence_score: int = 0
    validation_notes: List[str] = None
    exploitability: str = ""
    recommendation: str = ""
    
    def __post_init__(self):
        if self.validation_notes is None:
            self.validation_notes = []


class FindingValidator:
    """Validates security findings and assigns confidence scores."""
    
    # Framework protection patterns
    FRAMEWORK_PROTECTIONS = {
        'XSS': [
            # Auto-escaping templates
            (r'\.ejs\b', 'EJS auto-escaping (if enabled)'),
            (r'\.hbs\b', 'Handlebars auto-escaping'),
            (r'React\.createElement', 'React auto-escaping'),
            (r'\.jsx?\b', 'JSX auto-escaping'),
            (r'\.vue\b', 'Vue.js auto-escaping'),
            
            # Encoding functions
            (r'escape\w*Html', 'HTML escaping function'),
            (r'htmlspecialchars', 'PHP HTML encoding'),
            (r'encode\w*Html', 'HTML encoding'),
        ],
        'SQL Injection': [
            # Parameterized queries
            (r'\?|\$\d+', 'Parameterized query placeholder'),
            (r'prepare\s*\(', 'Prepared statement'),
            (r'\.bind\s*\(', 'Parameter binding'),
            (r'PDO::', 'PDO (supports prepared statements)'),
            
            # ORMs with protection
            (r'\.where\s*\(', 'ORM where clause (likely safe)'),
            (r'Eloquent', 'Laravel Eloquent ORM'),
            (r'Doctrine', 'Doctrine ORM'),
        ],
        'Command Injection': [
            # Safe alternatives
            (r'subprocess\.run\s*\(\s*\[', 'subprocess with list (safe)'),
            (r'child_process\.spawn\s*\(\s*["\'][^"\']+["\'],\s*\[', 'spawn with array (safe)'),
            (r'shlex\.quote', 'Shell escaping'),
        ],
        'Path Traversal': [
            # Path validation
            (r'realpath\s*\(', 'Path canonicalization'),
            (r'path\.normalize', 'Path normalization'),
            (r'\.basename\s*\(', 'Basename extraction'),
            (r'startswith\s*\(["\']/', 'Absolute path check'),
        ],
    }
    
    # Validation patterns (good sanitization)
    VALIDATION_PATTERNS = {
        'XSS': [
            r'DOMPurify\.sanitize',
            r'xss\-filters',
            r'validator\.escape',
            r'sanitize-html',
        ],
        'SQL Injection': [
            r'mysql_real_escape_string',
            r'mysqli_real_escape_string',
            r'pg_escape_string',
            r'addslashes',  # Weak but still counts
        ],
        'Path Traversal': [
            r'whitelist',
            r'allowedPaths',
            r'in\s+ALLOWED_',
            r'\.match\s*\(/\^[a-zA-Z0-9]/',  # Character whitelist
        ],
    }
    
    def __init__(self, project_root: Path):
        self.project_root = project_root
    
    def validate_finding(self, finding: Finding, file_content: str) -> Finding:
        """
        Validate a finding and assign confidence score.
        
        Validation process:
        1. Check for framework protections
        2. Check for explicit sanitization
        3. Verify data flow path
        4. Assess exploitability
        5. Assign confidence score
        """
        score_factors = {
            'has_clear_path': 0,
            'no_sanitization': 0,
            'no_framework_protection': 0,
            'exploitable': 0,
        }
        
        notes = []
        
        # 1. Check framework protections
        has_framework_protection, protection_notes = self._check_framework_protection(
            finding.vuln_type,
            finding.filepath,
            file_content
        )
        notes.extend(protection_notes)
        
        if not has_framework_protection:
            score_factors['no_framework_protection'] = 25
            notes.append("No framework-level protection detected")
        else:
            notes.append("Framework protection may be present (reduces confidence)")
        
        # 2. Check for explicit sanitization
        has_sanitization, sanitization_notes = self._check_sanitization(
            finding.vuln_type,
            finding.code_snippet,
            finding.data_flow or []
        )
        notes.extend(sanitization_notes)
        
        if not has_sanitization:
            score_factors['no_sanitization'] = 30
            notes.append("No explicit sanitization detected in data flow")
        else:
            notes.append("Sanitization present but may be insufficient")
        
        # 3. Verify clear path from input to sink
        has_clear_path = self._verify_data_path(finding)
        if has_clear_path:
            score_factors['has_clear_path'] = 25
            notes.append("Clear path from untrusted input to sink")
        else:
            notes.append("Unclear or indirect data flow path")
        
        # 4. Assess exploitability
        exploitability = self._assess_exploitability(finding, file_content)
        finding.exploitability = exploitability
        
        if exploitability in ['High', 'Critical']:
            score_factors['exploitable'] = 20
            notes.append(f"Exploitability: {exploitability}")
        
        # Calculate final confidence score
        confidence = sum(score_factors.values())
        
        # Adjust based on vuln type severity
        if finding.vuln_type in ['XSS', 'SQL Injection', 'Command Injection']:
            confidence = min(100, confidence + 10)  # Boost critical vuln types
        
        finding.confidence_score = confidence
        finding.validation_notes = notes
        
        # Generate recommendation
        finding.recommendation = self._generate_recommendation(finding)
        
        return finding
    
    def _check_framework_protection(
        self,
        vuln_type: str,
        filepath: str,
        content: str
    ) -> Tuple[bool, List[str]]:
        """Check if framework provides protection for this vulnerability."""
        notes = []
        
        if vuln_type not in self.FRAMEWORK_PROTECTIONS:
            return False, notes
        
        patterns = self.FRAMEWORK_PROTECTIONS[vuln_type]
        
        for pattern, description in patterns:
            if re.search(pattern, content):
                notes.append(f"Detected: {description}")
                return True, notes
        
        return False, notes
    
    def _check_sanitization(
        self,
        vuln_type: str,
        code_snippet: str,
        data_flow: List[Dict]
    ) -> Tuple[bool, List[str]]:
        """Check for explicit sanitization in code or data flow."""
        notes = []
        
        if vuln_type not in self.VALIDATION_PATTERNS:
            return False, notes
        
        patterns = self.VALIDATION_PATTERNS[vuln_type]
        
        # Check code snippet
        for pattern in patterns:
            if re.search(pattern, code_snippet, re.IGNORECASE):
                notes.append(f"Sanitization found: {pattern}")
                return True, notes
        
        # Check data flow
        for step in data_flow:
            step_code = step.get('code', '')
            for pattern in patterns:
                if re.search(pattern, step_code, re.IGNORECASE):
                    notes.append(f"Sanitization in flow: {pattern}")
                    return True, notes
        
        return False, notes
    
    def _verify_data_path(self, finding: Finding) -> bool:
        """Verify there's a clear path from input to sink."""
        # If we have data flow information, verify it's connected
        if finding.data_flow:
            return len(finding.data_flow) > 0
        
        # If we have input source info, it's likely a clear path
        if finding.input_source:
            return True
        
        return False
    
    def _assess_exploitability(self, finding: Finding, content: str) -> str:
        """
        Assess how exploitable this vulnerability is.
        Returns: Critical, High, Medium, Low
        """
        vuln_type = finding.vuln_type
        
        # Critical exploitability
        if vuln_type == 'Command Injection':
            if re.search(r'shell=True|shell_exec|system\(', finding.code_snippet):
                return 'Critical'
        
        if vuln_type == 'SQL Injection':
            if re.search(r'admin|password|user|email', finding.code_snippet, re.IGNORECASE):
                return 'Critical'
        
        # High exploitability
        if vuln_type == 'XSS':
            if 'innerHTML' in finding.code_snippet or 'eval' in finding.code_snippet:
                return 'High'
        
        if vuln_type == 'Path Traversal':
            if re.search(r'\.\./', finding.code_snippet):
                return 'High'
        
        # Medium by default for security issues
        if finding.input_source:
            return 'Medium'
        
        return 'Low'
    
    def _generate_recommendation(self, finding: Finding) -> str:
        """Generate specific remediation recommendation."""
        vuln_type = finding.vuln_type
        
        recommendations = {
            'XSS': (
                "Use framework's built-in escaping (e.g., JSX, template auto-escape). "
                "For dynamic HTML, use DOMPurify.sanitize(). "
                "Avoid innerHTML, eval(), and unescaped template variables."
            ),
            'SQL Injection': (
                "Use parameterized queries/prepared statements. "
                "Never concatenate user input into SQL queries. "
                "Use ORM query builders with parameter binding."
            ),
            'Command Injection': (
                "Avoid shell execution entirely. "
                "Use language/library APIs directly (e.g., subprocess.run with list). "
                "If shell is required, use strict input validation and shell escaping."
            ),
            'Path Traversal': (
                "Validate paths against a whitelist. "
                "Use path.normalize() or realpath() to canonicalize paths. "
                "Restrict file operations to a specific base directory."
            ),
            'SSRF': (
                "Validate URLs against a whitelist of allowed domains. "
                "Disable redirects or validate redirect targets. "
                "Use allow-lists rather than deny-lists for URL validation."
            ),
        }
        
        return recommendations.get(
            vuln_type,
            "Implement input validation, use framework security features, and apply defense in depth."
        )


def validate_findings_batch(findings: List[Dict], project_root: Path) -> List[Dict]:
    """Validate a batch of findings and return with confidence scores."""
    validator = FindingValidator(project_root)
    validated = []
    
    for finding_dict in findings:
        # Convert dict to Finding object
        finding = Finding(
            vuln_type=finding_dict['type'],
            filepath=finding_dict['filepath'],
            line_number=finding_dict['line'],
            code_snippet=finding_dict['code'],
            input_source=finding_dict.get('input_source'),
            data_flow=finding_dict.get('data_flow'),
        )
        
        # Read file content
        try:
            with open(finding.filepath, 'r', encoding='utf-8') as f:
                content = f.read()
        except Exception as e:
            finding.validation_notes = [f"Error reading file: {e}"]
            finding.confidence_score = 0
            validated.append(asdict(finding))
            continue
        
        # Validate
        validated_finding = validator.validate_finding(finding, content)
        validated.append(asdict(validated_finding))
    
    return validated


def main():
    """CLI entry point for finding validation."""
    import sys
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Validate security findings with confidence scoring'
    )
    parser.add_argument(
        'findings_file',
        type=Path,
        help='JSON file containing findings to validate'
    )
    parser.add_argument(
        '--project-root',
        type=Path,
        default=Path.cwd(),
        help='Project root directory'
    )
    parser.add_argument(
        '--output',
        '-o',
        type=Path,
        help='Output JSON file'
    )
    parser.add_argument(
        '--threshold',
        type=int,
        default=50,
        help='Confidence threshold for primary findings (default: 50)'
    )
    
    args = parser.parse_args()
    
    # Load findings
    with open(args.findings_file, 'r') as f:
        data = json.load(f)
    
    findings = data.get('findings', [])
    if isinstance(findings, dict):
        # Flatten if grouped by type
        findings = [f for group in findings.values() for f in group]
    
    # Validate
    validated = validate_findings_batch(findings, args.project_root)
    
    # Categorize by confidence
    high_confidence = [f for f in validated if f['confidence_score'] >= 80]
    medium_confidence = [f for f in validated if 50 <= f['confidence_score'] < 80]
    low_confidence = [f for f in validated if 20 <= f['confidence_score'] < 50]
    false_positives = [f for f in validated if f['confidence_score'] < 20]
    
    output = {
        'summary': {
            'total_findings': len(validated),
            'high_confidence': len(high_confidence),
            'medium_confidence': len(medium_confidence),
            'low_confidence': len(low_confidence),
            'false_positives': len(false_positives),
        },
        'high_confidence_findings': high_confidence,
        'medium_confidence_findings': medium_confidence,
        'low_confidence_findings': low_confidence,
        'false_positives': false_positives,
    }
    
    # Print summary
    print("\n=== Validation Summary ===", file=sys.stderr)
    print(f"Total findings validated: {len(validated)}", file=sys.stderr)
    print(f"High confidence (≥80): {len(high_confidence)}", file=sys.stderr)
    print(f"Medium confidence (50-79): {len(medium_confidence)}", file=sys.stderr)
    print(f"Low confidence (20-49): {len(low_confidence)}", file=sys.stderr)
    print(f"False positives (<20): {len(false_positives)}", file=sys.stderr)
    print("", file=sys.stderr)
    
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(output, f, indent=2)
        print(f"Results written to {args.output}", file=sys.stderr)
    else:
        print(json.dumps(output, indent=2))


if __name__ == '__main__':
    main()
