#!/usr/bin/env python3
"""
Data flow tracing utilities for security analysis.
Helps track data from inputs to sinks and vice versa.
"""

import re
import json
from pathlib import Path
from typing import Dict, List, Set, Tuple, Optional
from collections import defaultdict


class DataFlowTracer:
    """Trace data flow through code to identify tainted data paths."""
    
    # Common input sources
    INPUT_PATTERNS = {
        'User Input': [
            r'req\.query\.',
            r'req\.params\.',
            r'req\.body\.',
            r'req\.cookies\.',
            r'req\.headers\.',
            r'\$_GET\[',
            r'\$_POST\[',
            r'\$_REQUEST\[',
            r'\$_COOKIE\[',
            r'\$_SERVER\[',
            r'request\.args\.get',
            r'request\.form\.get',
            r'request\.GET',
            r'request\.POST',
        ],
        'File Upload': [
            r'req\.files\.',
            r'\$_FILES\[',
            r'request\.FILES',
        ],
        'External API': [
            r'fetch\s*\(',
            r'axios\.',
            r'requests\.',
            r'\$\.ajax',
        ],
        'Database': [
            r'\.findOne\(',
            r'\.find\(',
            r'\.query\(',
            r'SELECT\s+.*\s+FROM',
        ],
        'Third-Party': [
            r'process\.env\.',
            r'os\.getenv',
            r'config\.',
        ]
    }
    
    # Variable assignment patterns
    ASSIGNMENT_PATTERNS = [
        r'(const|let|var)\s+(\w+)\s*=\s*(.+)',  # JavaScript
        r'(\w+)\s*=\s*(.+)',  # Python, PHP, etc.
        r'(\w+)\s*:=\s*(.+)',  # Go
    ]
    
    # Sanitization/validation functions
    SANITIZATION_PATTERNS = [
        r'escape',
        r'sanitize',
        r'validate',
        r'htmlspecialchars',
        r'strip_tags',
        r'filter_var',
        r'prepared?Statement',
        r'parameterized',
        r'encode',
    ]
    
    def __init__(self, project_root: Path):
        self.project_root = project_root
        self.variable_map = defaultdict(list)  # Maps variable names to their sources
        self.taint_map = defaultdict(set)  # Maps variables to taint sources
        
    def identify_inputs(self, content: str, filepath: Path) -> List[Dict]:
        """Identify all input sources in a file."""
        inputs = []
        lines = content.split('\n')
        
        for input_type, patterns in self.INPUT_PATTERNS.items():
            for pattern in patterns:
                for line_num, line in enumerate(lines, 1):
                    matches = re.finditer(pattern, line)
                    for match in matches:
                        inputs.append({
                            'type': input_type,
                            'pattern': pattern,
                            'line': line_num,
                            'code': line.strip(),
                            'filepath': str(filepath),
                            'matched_text': match.group(0),
                        })
        
        return inputs
    
    def trace_variable(self, var_name: str, content: str) -> List[Dict]:
        """
        Trace where a variable is assigned and what it's assigned from.
        Returns list of assignments with source tracking.
        """
        assignments = []
        lines = content.split('\n')
        
        # Match variable assignments
        for line_num, line in enumerate(lines, 1):
            for pattern in self.ASSIGNMENT_PATTERNS:
                match = re.search(pattern, line)
                if match and var_name in match.group(0):
                    assignments.append({
                        'variable': var_name,
                        'line': line_num,
                        'code': line.strip(),
                        'source': self._extract_source(match),
                    })
        
        return assignments
    
    def _extract_source(self, match: re.Match) -> str:
        """Extract the source expression from an assignment."""
        groups = match.groups()
        # Last group typically contains the value being assigned
        return groups[-1].strip() if groups else ''
    
    def has_sanitization(self, code_snippet: str) -> Tuple[bool, List[str]]:
        """
        Check if code snippet includes sanitization/validation.
        Returns (has_sanitization, list of sanitization methods found).
        """
        found_methods = []
        for pattern in self.SANITIZATION_PATTERNS:
            if re.search(pattern, code_snippet, re.IGNORECASE):
                found_methods.append(pattern)
        
        return len(found_methods) > 0, found_methods
    
    def trace_forward(self, input_location: Dict, content: str) -> List[Dict]:
        """
        Trace data flow forward from an input source.
        Returns list of locations where the tainted data appears.
        """
        # Extract variable name from input
        input_line = input_location['code']
        var_pattern = r'(const|let|var)?\s*(\w+)\s*='
        match = re.search(var_pattern, input_line)
        
        if not match:
            return []
        
        var_name = match.group(2)
        lines = content.split('\n')
        
        flow_path = []
        for line_num, line in enumerate(lines, 1):
            if line_num <= input_location['line']:
                continue  # Skip lines before input
            
            # Check if variable is used
            if re.search(r'\b' + re.escape(var_name) + r'\b', line):
                has_san, methods = self.has_sanitization(line)
                flow_path.append({
                    'line': line_num,
                    'code': line.strip(),
                    'variable': var_name,
                    'sanitized': has_san,
                    'sanitization_methods': methods,
                })
        
        return flow_path
    
    def trace_backward(self, sink_location: Dict, content: str) -> List[Dict]:
        """
        Trace data flow backward from a sink.
        Returns list of potential input sources that feed this sink.
        """
        sink_line = sink_location['code']
        lines = content.split('\n')
        
        # Extract variables used in sink
        variables = self._extract_variables(sink_line)
        
        sources = []
        for var in variables:
            # Search backward for variable definition/assignment
            for line_num in range(sink_location['line'] - 1, 0, -1):
                line = lines[line_num - 1]
                
                # Check if this line defines/assigns the variable
                if re.search(rf'\b{re.escape(var)}\s*=', line):
                    has_san, methods = self.has_sanitization(line)
                    
                    # Check if assignment comes from an input source
                    input_type = self._identify_input_type(line)
                    
                    sources.append({
                        'variable': var,
                        'line': line_num,
                        'code': line.strip(),
                        'input_type': input_type,
                        'sanitized': has_san,
                        'sanitization_methods': methods,
                    })
                    break
        
        return sources
    
    def _extract_variables(self, code: str) -> List[str]:
        """Extract variable names from a code snippet."""
        # Simple extraction - matches identifiers
        return list(set(re.findall(r'\b([a-zA-Z_]\w*)\b', code)))
    
    def _identify_input_type(self, line: str) -> Optional[str]:
        """Identify if a line contains an input source and return its type."""
        for input_type, patterns in self.INPUT_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, line):
                    return input_type
        return None


def analyze_file(filepath: Path) -> Dict:
    """
    Perform complete data flow analysis on a file.
    Returns inputs, sinks, and traced flows.
    """
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
    except Exception as e:
        return {'error': str(e)}
    
    tracer = DataFlowTracer(filepath.parent)
    
    # Identify inputs
    inputs = tracer.identify_inputs(content, filepath)
    
    # Trace forward from each input
    flows = []
    for input_loc in inputs:
        flow = tracer.trace_forward(input_loc, content)
        if flow:
            flows.append({
                'input': input_loc,
                'flow_path': flow,
            })
    
    return {
        'filepath': str(filepath),
        'inputs': inputs,
        'flows': flows,
    }


def main():
    """CLI entry point for data flow analysis."""
    import sys
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Trace data flow in code for security analysis'
    )
    parser.add_argument(
        'target',
        type=Path,
        help='File or directory to analyze'
    )
    parser.add_argument(
        '--output',
        '-o',
        type=Path,
        help='Output JSON file'
    )
    
    args = parser.parse_args()
    
    if not args.target.exists():
        print(f"Error: {args.target} does not exist", file=sys.stderr)
        sys.exit(1)
    
    results = []
    
    if args.target.is_file():
        results.append(analyze_file(args.target))
    else:
        # Scan directory
        for filepath in args.target.rglob('*.{js,py,php,java}'):
            if filepath.is_file():
                results.append(analyze_file(filepath))
    
    output = {
        'total_files': len(results),
        'total_inputs': sum(len(r.get('inputs', [])) for r in results),
        'total_flows': sum(len(r.get('flows', [])) for r in results),
        'files': results,
    }
    
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(output, f, indent=2)
        print(f"Results written to {args.output}", file=sys.stderr)
    else:
        print(json.dumps(output, indent=2))


if __name__ == '__main__':
    main()
