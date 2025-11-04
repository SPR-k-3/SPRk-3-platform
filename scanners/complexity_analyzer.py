#!/usr/bin/env python3
"""
SPR{K}3 Engine 9: Code Complexity Analyzer
Analyzes code complexity, detects obfuscation, and identifies maintainability issues

Author: Dan Aridor - SPR{K}3 Security Research Team
Patent: US Provisional Application (October 8, 2025)

Detects:
- Cyclomatic complexity (McCabe)
- Cognitive complexity (Sonar)
- Obfuscation patterns (malware indicators)
- Maintainability issues
- Technical debt hotspots
"""

import ast
import os
import re
import json
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Set, Tuple, Optional
from collections import defaultdict
from dataclasses import dataclass, asdict
import statistics


@dataclass
class FunctionComplexity:
    """Complexity metrics for a single function"""
    name: str
    file: str
    line_number: int
    cyclomatic_complexity: int
    cognitive_complexity: int
    nesting_depth: int
    num_parameters: int
    lines_of_code: int
    has_suspicious_patterns: bool
    obfuscation_score: float  # 0.0-1.0
    issues: List[str]


@dataclass
class FileComplexity:
    """Complexity metrics for a file"""
    file_path: str
    total_functions: int
    avg_cyclomatic: float
    max_cyclomatic: int
    avg_cognitive: float
    max_cognitive: int
    avg_nesting: float
    max_nesting: int
    total_loc: int
    maintainability_score: float  # 0-100
    functions: List[FunctionComplexity]


@dataclass
class ComplexityReport:
    """Complete complexity analysis report"""
    repo_path: str
    analysis_date: str
    total_files: int
    total_functions: int
    avg_complexity: float
    high_complexity_functions: int
    obfuscated_functions: int
    technical_debt_score: float  # 0-100
    hotspots: List[Dict]
    file_reports: List[FileComplexity]


class ComplexityAnalyzer:
    """
    Code complexity analyzer using AST parsing
    Detects suspicious complexity patterns that may indicate obfuscation or malware
    """
    
    # Complexity thresholds (based on industry standards)
    CYCLOMATIC_LOW = 10
    CYCLOMATIC_MEDIUM = 20
    CYCLOMATIC_HIGH = 30
    
    COGNITIVE_LOW = 15
    COGNITIVE_MEDIUM = 25
    
    NESTING_WARNING = 4
    NESTING_CRITICAL = 6
    
    # Obfuscation indicators
    SUSPICIOUS_NAME_LENGTH = 50  # Very long variable names
    SUSPICIOUS_NAME_PATTERN = r'^[a-z]{1,2}[0-9]+$'  # Single letter + numbers
    
    def __init__(self, repo_path: str, output_dir: str = "./complexity_analysis"):
        self.repo_path = Path(repo_path)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        
        self.file_reports: List[FileComplexity] = []
        self.all_functions: List[FunctionComplexity] = []
        
        self.analysis_start = datetime.now().isoformat()
    
    def analyze_repository(self) -> ComplexityReport:
        """Main analysis pipeline"""
        print(f"\n[*] Analyzing repository: {self.repo_path.name}")
        
        # Find all Python files
        py_files = self._find_python_files()
        print(f"[*] Found {len(py_files)} Python files")
        
        # Analyze each file
        for py_file in py_files:
            file_report = self._analyze_file(py_file)
            if file_report:
                self.file_reports.append(file_report)
                self.all_functions.extend(file_report.functions)
        
        # Generate summary report
        report = self._generate_report()
        
        # Save report
        self._save_report(report)
        
        return report
    
    def _find_python_files(self) -> List[Path]:
        """Find all Python files in repository"""
        py_files = []
        
        for root, dirs, files in os.walk(self.repo_path):
            # Skip common ignore directories
            dirs[:] = [d for d in dirs if d not in {'.git', '__pycache__', 'venv', 'env', 'node_modules'}]
            
            for file in files:
                if file.endswith('.py'):
                    py_files.append(Path(root) / file)
        
        return py_files
    
    def _analyze_file(self, file_path: Path) -> Optional[FileComplexity]:
        """Analyze a single Python file"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                source = f.read()
            
            # Parse AST
            tree = ast.parse(source, filename=str(file_path))
            
            # Analyze all functions
            functions = []
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    func_complexity = self._analyze_function(node, file_path, source)
                    if func_complexity:
                        functions.append(func_complexity)
            
            if not functions:
                return None
            
            # Calculate file-level metrics
            cyclomatic_scores = [f.cyclomatic_complexity for f in functions]
            cognitive_scores = [f.cognitive_complexity for f in functions]
            nesting_scores = [f.nesting_depth for f in functions]
            
            avg_cyclomatic = statistics.mean(cyclomatic_scores)
            avg_cognitive = statistics.mean(cognitive_scores)
            avg_nesting = statistics.mean(nesting_scores)
            
            # Calculate maintainability score
            maintainability = self._calculate_maintainability(
                avg_cyclomatic, avg_cognitive, avg_nesting, len(functions)
            )
            
            # Count total lines
            total_loc = sum(f.lines_of_code for f in functions)
            
            file_report = FileComplexity(
                file_path=str(file_path.relative_to(self.repo_path)),
                total_functions=len(functions),
                avg_cyclomatic=avg_cyclomatic,
                max_cyclomatic=max(cyclomatic_scores),
                avg_cognitive=avg_cognitive,
                max_cognitive=max(cognitive_scores),
                avg_nesting=avg_nesting,
                max_nesting=max(nesting_scores),
                total_loc=total_loc,
                maintainability_score=maintainability,
                functions=functions
            )
            
            return file_report
            
        except Exception as e:
            # Skip files that can't be parsed
            return None
    
    def _analyze_function(self, node: ast.FunctionDef, file_path: Path, source: str) -> Optional[FunctionComplexity]:
        """Analyze a single function"""
        try:
            # Calculate cyclomatic complexity
            cyclomatic = self._calculate_cyclomatic(node)
            
            # Calculate cognitive complexity
            cognitive = self._calculate_cognitive(node)
            
            # Calculate nesting depth
            nesting = self._calculate_nesting_depth(node)
            
            # Count parameters
            num_params = len(node.args.args)
            
            # Calculate lines of code
            loc = self._calculate_loc(node, source)
            
            # Check for obfuscation patterns
            obfuscation_score, suspicious, issues = self._detect_obfuscation(node)
            
            func_complexity = FunctionComplexity(
                name=node.name,
                file=str(file_path.relative_to(self.repo_path)),
                line_number=node.lineno,
                cyclomatic_complexity=cyclomatic,
                cognitive_complexity=cognitive,
                nesting_depth=nesting,
                num_parameters=num_params,
                lines_of_code=loc,
                has_suspicious_patterns=suspicious,
                obfuscation_score=obfuscation_score,
                issues=issues
            )
            
            return func_complexity
            
        except Exception as e:
            return None
    
    def _calculate_cyclomatic(self, node: ast.FunctionDef) -> int:
        """
        Calculate McCabe cyclomatic complexity
        Counts decision points: if, for, while, and, or, except, with
        """
        complexity = 1  # Base complexity
        
        for child in ast.walk(node):
            # Decision points
            if isinstance(child, (ast.If, ast.While, ast.For, ast.AsyncFor)):
                complexity += 1
            elif isinstance(child, ast.ExceptHandler):
                complexity += 1
            elif isinstance(child, ast.With):
                complexity += 1
            elif isinstance(child, ast.BoolOp):
                # Each 'and' or 'or' adds complexity
                complexity += len(child.values) - 1
            elif isinstance(child, ast.comprehension):
                # List/dict comprehensions with if clauses
                complexity += len(child.ifs)
        
        return complexity
    
    def _calculate_cognitive(self, node: ast.FunctionDef) -> int:
        """
        Calculate cognitive complexity (similar to SonarQube)
        Penalizes nested control structures more heavily
        """
        complexity = 0
        
        def visit_node(n, nesting_level=0):
            nonlocal complexity
            
            # Increment for control structures
            if isinstance(n, (ast.If, ast.While, ast.For, ast.AsyncFor)):
                complexity += 1 + nesting_level
                # Recurse with increased nesting
                for child in ast.iter_child_nodes(n):
                    visit_node(child, nesting_level + 1)
                return
            
            elif isinstance(n, ast.BoolOp):
                # Penalize each boolean operator
                complexity += len(n.values) - 1
            
            elif isinstance(n, ast.ExceptHandler):
                complexity += 1 + nesting_level
            
            # Continue visiting children
            for child in ast.iter_child_nodes(n):
                visit_node(child, nesting_level)
        
        visit_node(node)
        return complexity
    
    def _calculate_nesting_depth(self, node: ast.FunctionDef) -> int:
        """Calculate maximum nesting depth"""
        max_depth = 0
        
        def get_depth(n, current_depth=0):
            nonlocal max_depth
            max_depth = max(max_depth, current_depth)
            
            # Increment depth for control structures
            if isinstance(n, (ast.If, ast.While, ast.For, ast.AsyncFor, ast.With, ast.Try)):
                current_depth += 1
            
            for child in ast.iter_child_nodes(n):
                get_depth(child, current_depth)
        
        get_depth(node)
        return max_depth
    
    def _calculate_loc(self, node: ast.FunctionDef, source: str) -> int:
        """Calculate lines of code (excluding blank lines and comments)"""
        try:
            # Get function source lines
            lines = source.split('\n')
            start_line = node.lineno - 1
            
            # Find end line
            end_line = start_line
            if hasattr(node, 'end_lineno') and node.end_lineno:
                end_line = node.end_lineno
            else:
                # Estimate end line
                end_line = min(start_line + 50, len(lines))
            
            # Count non-empty, non-comment lines
            loc = 0
            for line in lines[start_line:end_line]:
                stripped = line.strip()
                if stripped and not stripped.startswith('#'):
                    loc += 1
            
            return loc
        except:
            return 0
    
    def _detect_obfuscation(self, node: ast.FunctionDef) -> Tuple[float, bool, List[str]]:
        """
        Detect potential code obfuscation
        Returns: (obfuscation_score, is_suspicious, issues)
        """
        issues = []
        score = 0.0
        
        # Check function name
        if len(node.name) > self.SUSPICIOUS_NAME_LENGTH:
            issues.append(f"Unusually long function name ({len(node.name)} chars)")
            score += 0.3
        
        if len(node.name) == 1:
            issues.append("Single-character function name")
            score += 0.2
        
        # Collect all variable names
        var_names = []
        for child in ast.walk(node):
            if isinstance(child, ast.Name):
                var_names.append(child.id)
        
        # Check for suspicious naming patterns
        if var_names:
            suspicious_names = [
                name for name in var_names 
                if re.match(self.SUSPICIOUS_NAME_PATTERN, name)
            ]
            
            if len(suspicious_names) > len(var_names) * 0.3:
                issues.append(f"High ratio of suspicious variable names ({len(suspicious_names)}/{len(var_names)})")
                score += 0.3
        
        # Check for excessive string operations (obfuscation technique)
        string_ops = sum(1 for child in ast.walk(node) if isinstance(child, ast.BinOp) and isinstance(child.op, ast.Add))
        if string_ops > 20:
            issues.append(f"Excessive string concatenation ({string_ops} operations)")
            score += 0.2
        
        # Check for eval/exec (code obfuscation red flag)
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                if isinstance(child.func, ast.Name) and child.func.id in {'eval', 'exec', 'compile'}:
                    issues.append(f"Dynamic code execution: {child.func.id}()")
                    score += 0.4
        
        # Check for base64/encoding usage (common in obfuscated code)
        for child in ast.walk(node):
            if isinstance(child, ast.Import):
                for alias in child.names:
                    if 'base64' in alias.name or 'binascii' in alias.name:
                        issues.append(f"Encoding library import: {alias.name}")
                        score += 0.1
        
        score = min(1.0, score)
        is_suspicious = score >= 0.5
        
        return score, is_suspicious, issues
    
    def _calculate_maintainability(self, avg_cyclomatic: float, avg_cognitive: float, 
                                   avg_nesting: float, num_functions: int) -> float:
        """
        Calculate maintainability score (0-100)
        Based on complexity metrics
        """
        score = 100.0
        
        # Penalize high cyclomatic complexity
        if avg_cyclomatic > self.CYCLOMATIC_HIGH:
            score -= 30
        elif avg_cyclomatic > self.CYCLOMATIC_MEDIUM:
            score -= 20
        elif avg_cyclomatic > self.CYCLOMATIC_LOW:
            score -= 10
        
        # Penalize high cognitive complexity
        if avg_cognitive > self.COGNITIVE_MEDIUM:
            score -= 25
        elif avg_cognitive > self.COGNITIVE_LOW:
            score -= 15
        
        # Penalize deep nesting
        if avg_nesting > self.NESTING_CRITICAL:
            score -= 20
        elif avg_nesting > self.NESTING_WARNING:
            score -= 10
        
        # Penalize very large files (too many functions)
        if num_functions > 50:
            score -= 15
        elif num_functions > 30:
            score -= 10
        
        return max(0.0, min(100.0, score))
    
    def _generate_report(self) -> ComplexityReport:
        """Generate summary complexity report"""
        
        if not self.all_functions:
            return ComplexityReport(
                repo_path=str(self.repo_path),
                analysis_date=self.analysis_start,
                total_files=0,
                total_functions=0,
                avg_complexity=0.0,
                high_complexity_functions=0,
                obfuscated_functions=0,
                technical_debt_score=100.0,
                hotspots=[],
                file_reports=[]
            )
        
        # Calculate averages
        avg_complexity = statistics.mean([f.cyclomatic_complexity for f in self.all_functions])
        
        # Count high complexity functions
        high_complexity = sum(
            1 for f in self.all_functions 
            if f.cyclomatic_complexity > self.CYCLOMATIC_HIGH
        )
        
        # Count obfuscated functions
        obfuscated = sum(1 for f in self.all_functions if f.has_suspicious_patterns)
        
        # Calculate technical debt score
        technical_debt = self._calculate_technical_debt()
        
        # Identify hotspots (worst offenders)
        hotspots = self._identify_hotspots()
        
        report = ComplexityReport(
            repo_path=str(self.repo_path),
            analysis_date=self.analysis_start,
            total_files=len(self.file_reports),
            total_functions=len(self.all_functions),
            avg_complexity=avg_complexity,
            high_complexity_functions=high_complexity,
            obfuscated_functions=obfuscated,
            technical_debt_score=technical_debt,
            hotspots=hotspots,
            file_reports=self.file_reports
        )
        
        return report
    
    def _calculate_technical_debt(self) -> float:
        """
        Calculate overall technical debt score (0-100, higher = more debt)
        """
        if not self.all_functions:
            return 0.0
        
        debt = 0.0
        
        # High complexity functions
        high_complex_ratio = sum(
            1 for f in self.all_functions 
            if f.cyclomatic_complexity > self.CYCLOMATIC_HIGH
        ) / len(self.all_functions)
        debt += high_complex_ratio * 40
        
        # Obfuscated code
        obfuscated_ratio = sum(
            1 for f in self.all_functions 
            if f.has_suspicious_patterns
        ) / len(self.all_functions)
        debt += obfuscated_ratio * 30
        
        # Deep nesting
        deep_nesting_ratio = sum(
            1 for f in self.all_functions 
            if f.nesting_depth > self.NESTING_CRITICAL
        ) / len(self.all_functions)
        debt += deep_nesting_ratio * 20
        
        # Very long functions
        long_func_ratio = sum(
            1 for f in self.all_functions 
            if f.lines_of_code > 100
        ) / len(self.all_functions)
        debt += long_func_ratio * 10
        
        return min(100.0, debt)
    
    def _identify_hotspots(self) -> List[Dict]:
        """Identify the worst complexity hotspots"""
        # Sort by complexity
        sorted_funcs = sorted(
            self.all_functions, 
            key=lambda f: f.cyclomatic_complexity, 
            reverse=True
        )
        
        hotspots = []
        for func in sorted_funcs[:10]:  # Top 10
            hotspot = {
                'function': func.name,
                'file': func.file,
                'line': func.line_number,
                'cyclomatic_complexity': func.cyclomatic_complexity,
                'cognitive_complexity': func.cognitive_complexity,
                'nesting_depth': func.nesting_depth,
                'lines_of_code': func.lines_of_code,
                'obfuscation_score': func.obfuscation_score,
                'issues': func.issues
            }
            hotspots.append(hotspot)
        
        return hotspots
    
    def _save_report(self, report: ComplexityReport):
        """Save report to JSON file"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        report_file = self.output_dir / f"complexity_report_{timestamp}.json"
        
        # Convert to dict for JSON
        report_dict = asdict(report)
        
        with open(report_file, 'w') as f:
            json.dump(report_dict, f, indent=2)
        
        print(f"\n[+] Report saved to: {report_file}")
    
    def print_summary(self, report: ComplexityReport):
        """Print human-readable summary"""
        print("\n" + "="*80)
        print("SPR{K}3 CODE COMPLEXITY ANALYSIS")
        print("="*80)
        
        print(f"\n[*] Repository: {report.repo_path}")
        print(f"[*] Files Analyzed: {report.total_files}")
        print(f"[*] Functions Analyzed: {report.total_functions}")
        print(f"[*] Average Complexity: {report.avg_complexity:.1f}")
        
        # Technical debt assessment
        if report.technical_debt_score < 20:
            debt_status = "✅ LOW"
        elif report.technical_debt_score < 40:
            debt_status = "⚠️  MODERATE"
        elif report.technical_debt_score < 60:
            debt_status = "🔴 HIGH"
        else:
            debt_status = "💀 CRITICAL"
        
        print(f"\n📊 Technical Debt Score: {report.technical_debt_score:.1f}/100 ({debt_status})")
        
        print(f"\n🚨 Issues Found:")
        print(f"   High Complexity Functions: {report.high_complexity_functions}")
        print(f"   Potentially Obfuscated: {report.obfuscated_functions}")
        
        if report.hotspots:
            print(f"\n🔥 Top Complexity Hotspots:")
            for i, hotspot in enumerate(report.hotspots[:5], 1):
                print(f"\n   {i}. {hotspot['function']} ({hotspot['file']}:{hotspot['line']})")
                print(f"      Cyclomatic: {hotspot['cyclomatic_complexity']}, " +
                      f"Cognitive: {hotspot['cognitive_complexity']}, " +
                      f"Nesting: {hotspot['nesting_depth']}")
                if hotspot['issues']:
                    print(f"      Issues: {', '.join(hotspot['issues'][:2])}")
        
        print("\n" + "="*80)


def main():
    """Main execution"""
    import sys
    
    if len(sys.argv) < 2:
        print("""
SPR{K}3 Code Complexity Analyzer

Usage:
    python3 complexity_analyzer.py <repository_path>

Example:
    python3 complexity_analyzer.py ~/pytorch_repo

Options:
    --output-dir DIR    Output directory (default: ./complexity_analysis)
        """)
        sys.exit(1)
    
    repo_path = sys.argv[1]
    output_dir = "./complexity_analysis"
    
    for i, arg in enumerate(sys.argv):
        if arg == '--output-dir' and i + 1 < len(sys.argv):
            output_dir = sys.argv[i + 1]
    
    print("""
    ╔═══════════════════════════════════════════════════════════════╗
    ║  SPR{K}3 Engine 9: Code Complexity Analyzer                  ║
    ║  Cyclomatic, Cognitive, and Obfuscation Detection             ║
    ║                                                               ║
    ║  Author: Dan Aridor - SPR{K}3 Security Research Team         ║
    ║  Patent: US Provisional (October 8, 2025)                    ║
    ╚═══════════════════════════════════════════════════════════════╝
    """)
    
    # Initialize analyzer
    analyzer = ComplexityAnalyzer(repo_path, output_dir)
    
    # Run analysis
    report = analyzer.analyze_repository()
    
    # Print summary
    analyzer.print_summary(report)
    
    print(f"\n[+] Analysis complete!\n")


if __name__ == "__main__":
    main()
