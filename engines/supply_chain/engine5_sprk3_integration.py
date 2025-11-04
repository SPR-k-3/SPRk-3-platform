import json
from pathlib import Path

class Engine5Scanner:
    def __init__(self, repo_path: str, company: str = '', repository: str = ''):
        self.repo_path = Path(repo_path)
        self.company = company or self.repo_path.name
        self.repository = repository or self.repo_path.name
    
    def scan(self):
        vulns = []
        for py_file in self.repo_path.rglob('*.py'):
            try:
                with open(py_file, 'r', encoding='utf-8', errors='ignore') as f:
                    lines = f.read().split('\n')
                
                for line_num, line in enumerate(lines, 1):
                    if 'torch.load' in line and 'weights_only' not in line:
                        vulns.append(self._create_vuln('SC-001', str(py_file), line_num, line.strip(), 'critical', 0.95, 'Unsafe torch.load'))
                    if 'pickle.load' in line:
                        vulns.append(self._create_vuln('SC-001', str(py_file), line_num, line.strip(), 'critical', 0.95, 'Unsafe pickle.load'))
                    if 'trust_remote_code=True' in line:
                        vulns.append(self._create_vuln('SC-007', str(py_file), line_num, line.strip(), 'high', 0.85, 'trust_remote_code=True'))
                    if 'load_dataset' in line:
                        vulns.append(self._create_vuln('SC-006', str(py_file), line_num, line.strip(), 'high', 0.70, 'load_dataset'))
                    if any(x in line for x in ['exec(', 'eval(', '__reduce__']):
                        vulns.append(self._create_vuln('SC-003', str(py_file), line_num, line.strip(), 'critical', 0.98, 'exec/eval'))
            except:
                pass
        
        return {'metadata': {}, 'filter_stats': {'total': len(vulns), 'filtered': len(vulns)}, 'vulnerabilities': vulns}
    
    def _create_vuln(self, rule_id, file_path, line_num, code, severity, confidence, desc):
        min_b, max_b = self._bounty(severity, confidence)
        return {'type': rule_id, 'company': self.company, 'repository': self.repository, 'severity': severity.upper(), 'confidence': confidence, 'priority_score': self._priority(severity, confidence), 'bounty_range': [min_b, max_b], 'file': file_path, 'line': line_num, 'description': desc, 'code_snippet': code}
    
    @staticmethod
    def _bounty(severity, confidence):
        base = {'critical': (5000, 20000), 'high': (2000, 10000), 'medium': (500, 2000)}
        min_b, max_b = base.get(severity, (0, 0))
        return (int(min_b * confidence * 1.2), int(max_b * confidence * 1.2))
    
    @staticmethod
    def _priority(severity, confidence):
        weights = {'critical': 90, 'high': 70, 'medium': 50}
        return weights.get(severity, 50) * confidence

if __name__ == '__main__':
    import sys
    repo = sys.argv[1] if len(sys.argv) > 1 else '.'
    scanner = Engine5Scanner(repo)
    results = scanner.scan()
    total_min = sum(v['bounty_range'][0] for v in results['vulnerabilities'])
    total_max = sum(v['bounty_range'][1] for v in results['vulnerabilities'])
    print(f"\nEngine 5 Scan: {len(results['vulnerabilities'])} findings")
    print(f"Estimated bounty: ${total_min:,} - ${total_max:,}\n")
    with open(Path(repo) / 'engine5_findings.json', 'w') as f:
        json.dump(results, f, indent=2)
