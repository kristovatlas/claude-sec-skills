#!/usr/bin/env python3
"""
Pattern matcher for identifying security-sensitive sinks in code.
Supports multiple languages and frameworks.
"""

import re
import json
from pathlib import Path
from typing import Dict, List, Tuple


class SinkPatterns:
    """Pattern definitions for security sinks by vulnerability type."""
    
    # XSS Sinks
    XSS_PATTERNS = [
        # JavaScript DOM manipulation
        r'\.innerHTML\s*=',
        r'\.outerHTML\s*=',
        r'document\.write\(',
        r'document\.writeln\(',
        r'\.insertAdjacentHTML\(',
        
        # Dangerous JavaScript execution
        r'\beval\s*\(',
        r'new\s+Function\s*\(',
        r'setTimeout\s*\(\s*["\']',
        r'setInterval\s*\(\s*["\']',
        
        # Attribute/URL sinks
        r'\.href\s*=',
        r'\.src\s*=',
        r'\.action\s*=',
        r'\.formAction\s*=',
        
        # jQuery patterns
        r'\$\([^)]*\)\.html\(',
        r'\$\([^)]*\)\.append\(',
        r'\$\([^)]*\)\.prepend\(',
        
        # React dangerous patterns
        r'dangerouslySetInnerHTML',
        
        # Template engines (when not auto-escaping)
        r'\{\{\{.*?\}\}\}',  # Handlebars unescaped
        r'<%=.*?%>',  # EJS unescaped
    ]
    
    # SQL Injection Sinks
    SQLI_PATTERNS = [
        # String concatenation in queries
        r'(SELECT|INSERT|UPDATE|DELETE|FROM|WHERE).*?\+\s*\w+',
        r'(SELECT|INSERT|UPDATE|DELETE|FROM|WHERE).*?\.format\(',
        r'(SELECT|INSERT|UPDATE|DELETE|FROM|WHERE).*?f["\']',
        
        # Unsafe query execution
        r'\.execute\s*\(\s*["\'].*?\+',
        r'\.query\s*\(\s*["\'].*?\+',
        r'\.raw\s*\(',
        r'connection\.query\s*\(',
        
        # ORM raw queries
        r'\.raw\s*\(\s*["\']',
        r'executeSql\s*\(',
        r'executeQuery\s*\(',
    ]
    
    # Command Injection Sinks
    CMDI_PATTERNS = [
        r'\bexec\s*\(',
        r'\beval\s*\(',  # Also XSS, but included for completeness
        r'\bsystem\s*\(',
        r'shell_exec\s*\(',
        r'passthru\s*\(',
        r'popen\s*\(',
        r'proc_open\s*\(',
        r'subprocess\.call\s*\(',
        r'subprocess\.run\s*\(',
        r'os\.system\s*\(',
        r'child_process\.exec\s*\(',
        r'child_process\.spawn\s*\(',
    ]
    
    # Path Traversal Sinks
    PATH_TRAVERSAL_PATTERNS = [
        r'(open|file_get_contents|readfile|fopen)\s*\(',
        r'(include|require|include_once|require_once)\s*\(',
        r'fs\.readFile\s*\(',
        r'fs\.readFileSync\s*\(',
        r'path\.join\s*\(',
        r'os\.path\.join\s*\(',
    ]
    
    # SSRF Sinks
    SSRF_PATTERNS = [
        r'fetch\s*\(',
        r'axios\.\w+\s*\(',
        r'\$\.ajax\s*\(',
        r'\$\.get\s*\(',
        r'\$\.post\s*\(',
        r'urllib\.request\.urlopen\s*\(',
        r'requests\.\w+\s*\(',
        r'file_get_contents\s*\(\s*["\']http',
        r'curl_exec\s*\(',
    ]
    
    # Deserialization Sinks
    DESERIALIZATION_PATTERNS = [
        r'unserialize\s*\(',
        r'pickle\.loads\s*\(',
        r'yaml\.load\s*\(',
        r'JSON\.parse\s*\(',
        r'eval\s*\(',  # When used for deserialization
    ]


def find_sinks_in_file(filepath: Path, content: str) -> List[Dict]:
    """
    Find all security sinks in a file.
    
    Returns list of findings with:
    - type: vulnerability type
    - pattern: matched pattern
    - line: line number
    - code: code snippet
    - filepath: file path
    """
    findings = []
    lines = content.split('\n')
    
    patterns_by_type = {
        'XSS': SinkPatterns.XSS_PATTERNS,
        'SQL Injection': SinkPatterns.SQLI_PATTERNS,
        'Command Injection': SinkPatterns.CMDI_PATTERNS,
        'Path Traversal': SinkPatterns.PATH_TRAVERSAL_PATTERNS,
        'SSRF': SinkPatterns.SSRF_PATTERNS,
        'Insecure Deserialization': SinkPatterns.DESERIALIZATION_PATTERNS,
    }
    
    for vuln_type, patterns in patterns_by_type.items():
        for pattern in patterns:
            for line_num, line in enumerate(lines, 1):
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append({
                        'type': vuln_type,
                        'pattern': pattern,
                        'line': line_num,
                        'code': line.strip(),
                        'filepath': str(filepath),
                    })
    
    return findings


def scan_directory(directory: Path, extensions: List[str] = None) -> Dict:
    """
    Recursively scan directory for security sinks.
    
    Args:
        directory: Root directory to scan
        extensions: File extensions to scan (default: common web extensions)
    
    Returns:
        Dictionary mapping vulnerability types to findings
    """
    if extensions is None:
        extensions = [
            '.js', '.jsx', '.ts', '.tsx',  # JavaScript/TypeScript
            '.py',  # Python
            '.php',  # PHP
            '.java',  # Java
            '.rb',  # Ruby
            '.go',  # Go
            '.cs',  # C#
            '.html', '.ejs', '.hbs',  # Templates
        ]
    
    all_findings = []
    
    for filepath in directory.rglob('*'):
        if filepath.suffix in extensions and filepath.is_file():
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    content = f.read()
                    findings = find_sinks_in_file(filepath, content)
                    all_findings.extend(findings)
            except Exception as e:
                print(f"Error reading {filepath}: {e}")
    
    # Group by vulnerability type
    grouped = {}
    for finding in all_findings:
        vuln_type = finding['type']
        if vuln_type not in grouped:
            grouped[vuln_type] = []
        grouped[vuln_type].append(finding)
    
    return grouped


def main():
    """CLI entry point for sink detection."""
    import sys
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Find security-sensitive sinks in code'
    )
    parser.add_argument(
        'directory',
        type=Path,
        help='Directory to scan'
    )
    parser.add_argument(
        '--output',
        '-o',
        type=Path,
        help='Output JSON file (default: print to stdout)'
    )
    parser.add_argument(
        '--extensions',
        nargs='+',
        help='File extensions to scan (e.g., .js .py)'
    )
    
    args = parser.parse_args()
    
    if not args.directory.exists():
        print(f"Error: Directory {args.directory} does not exist", file=sys.stderr)
        sys.exit(1)
    
    findings = scan_directory(args.directory, args.extensions)
    
    # Summary
    total = sum(len(v) for v in findings.values())
    print(f"\n=== Sink Detection Summary ===", file=sys.stderr)
    print(f"Total sinks found: {total}", file=sys.stderr)
    for vuln_type, items in sorted(findings.items()):
        print(f"  {vuln_type}: {len(items)}", file=sys.stderr)
    print("", file=sys.stderr)
    
    # Output
    output = {
        'summary': {
            'total_sinks': total,
            'by_type': {k: len(v) for k, v in findings.items()}
        },
        'findings': findings
    }
    
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(output, f, indent=2)
        print(f"Results written to {args.output}", file=sys.stderr)
    else:
        print(json.dumps(output, indent=2))


if __name__ == '__main__':
    main()
