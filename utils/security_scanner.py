import os
import json
import re
import subprocess
import logging
from pathlib import Path
from datetime import datetime

# Configuration
LOG_FILE = "security_scan_history.log"
REPORT_JSON = "security_reports/report_latest.json"
REPORT_MD = "security_reports/report_latest.md"
SECRET_PATTERNS = {
    "Google API Key": r"AIzaSy[A-Za-z0-9_-]{20,}",
    "Generic Secret": r"(?:key|api|token|secret|password|passwd|auth)(?:[\s|'|\"]*)[:|=](?:[\s|'|\"]*)([a-zA-Z0-9]{16,})",
    "Private Key": r"-----BEGIN RSA PRIVATE KEY-----",
    "Generic Token": r"ghp_[a-zA-Z0-9]{36}|glpat-[a-zA-Z0-9]{20}",
}

class SecurityScanner:
    def __init__(self, root_dir):
        self.root_dir = Path(root_dir)
        self.results = {
            "timestamp": datetime.now().isoformat(),
            "root_dir": str(self.root_dir),
            "gitleaks": {"status": "Not Run", "leaks": []},
            "regex_scan": {"total_leaks": 0, "files_with_leaks": {}}
        }
        self.setup_logging()

    def setup_logging(self):
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s [%(levelname)s] %(message)s',
            handlers=[
                logging.FileHandler(LOG_FILE),
                logging.StreamHandler()
            ]
        )

    def run_gitleaks(self):
        logging.info("🔍 Running Gitleaks scan...")
        try:
            # Check if gitleaks is installed
            subprocess.run(["gitleaks", "version"], capture_output=True, check=True)
            
            # Run gitleaks detect
            result = subprocess.run(
                ["gitleaks", "detect", "--source", str(self.root_dir), "--no-git", "-v"],
                capture_output=True, text=True
            )
            
            if result.returncode == 0:
                self.results["gitleaks"]["status"] = "Success (No Leaks)"
                logging.info("✅ Gitleaks: No leaks detected.")
            else:
                self.results["gitleaks"]["status"] = "Leaks Found"
                logging.warning("❌ Gitleaks: Potential leaks detected in history.")
        except Exception as e:
            self.results["gitleaks"]["status"] = f"Error: {str(e)}"
            logging.error(f"⚠️ Gitleaks execution failed: {e}")

    def scan_notebook(self, file_path):
        leaks = []
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            for i, cell in enumerate(data.get('cells', [])):
                cell_type = cell.get('cell_type', 'unknown')
                source = "".join(cell.get('source', []))
                
                # Scan code and markdown
                for label, pattern in SECRET_PATTERNS.items():
                    matches = re.finditer(pattern, source)
                    for match in matches:
                        leak = {
                            "type": label,
                            "location": f"Cell {i} ({cell_type})",
                            "snippet": source[max(0, match.start()-10):min(len(source), match.end()+10)]
                        }
                        leaks.append(leak)
                
                # Scan outputs
                outputs = json.dumps(cell.get('outputs', []))
                for label, pattern in SECRET_PATTERNS.items():
                    if re.search(pattern, outputs):
                        leaks.append({
                            "type": f"{label} (in output)",
                            "location": f"Cell {i} output",
                            "snippet": "[Sensitive output redacted]"
                        })
        except Exception as e:
            logging.debug(f"Could not scan notebook {file_path}: {e}")
        return leaks

    def scan_regular_file(self, file_path):
        leaks = []
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line_num, line in enumerate(f, 1):
                    for label, pattern in SECRET_PATTERNS.items():
                        match = re.search(pattern, line)
                        if match:
                            leaks.append({
                                "type": label,
                                "location": f"Line {line_num}",
                                "snippet": line.strip()[:50]
                            })
        except Exception as e:
            logging.debug(f"Could not scan file {file_path}: {e}")
        return leaks

    def full_scan(self):
        logging.info("📝 Starting custom regex scan...")
        exclude_dirs = {'.git', 'node_modules', '__pycache__', '.venv', 'venv', 'security_reports', 'outputs'}
        include_exts = {'.py', '.ipynb', '.env', '.json', '.sh', '.yml', '.yaml', '.txt', '.md'}

        for path in self.root_dir.rglob('*'):
            if any(part in exclude_dirs for part in path.parts):
                continue
            
            if path.is_file() and path.suffix in include_exts:
                file_leaks = []
                if path.suffix == '.ipynb':
                    file_leaks = self.scan_notebook(path)
                else:
                    file_leaks = self.scan_regular_file(path)
                
                if file_leaks:
                    rel_path = str(path.relative_to(self.root_dir))
                    self.results["regex_scan"]["files_with_leaks"][rel_path] = file_leaks
                    self.results["regex_scan"]["total_leaks"] += len(file_leaks)
                    logging.warning(f"❌ Found {len(file_leaks)} potential leak(s) in {rel_path}")

    def generate_reports(self):
        Path("security_reports").mkdir(exist_ok=True)
        
        with open(REPORT_JSON, 'w') as f:
            json.dump(self.results, f, indent=4)
        
        with open(REPORT_MD, 'w') as f:
            f.write(f"# Security Scan Report - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            f.write(f"## Summary\n")
            f.write(f"- **Timestamp:** {self.results['timestamp']}\n")
            f.write(f"- **Gitleaks Status:** {self.results['gitleaks']['status']}\n")
            f.write(f"- **Total Regex Leaks:** {self.results['regex_scan']['total_leaks']}\n")
            f.write(f"- **Files impacted:** {len(self.results['regex_scan']['files_with_leaks'])}\n\n")
            
            if self.results['regex_scan']['total_leaks'] > 0:
                f.write("## Findings\n")
                for file, leaks in self.results['regex_scan']['files_with_leaks'].items():
                    f.write(f"### `{file}`\n")
                    for l in leaks:
                        f.write(f"- **{l['type']}** at {l['location']}: `{l['snippet']}`\n")
                    f.write("\n")
        
        logging.info(f"📊 Reports updated: {REPORT_JSON} and {REPORT_MD}")

if __name__ == "__main__":
    scanner = SecurityScanner(os.getcwd())
    scanner.run_gitleaks()
    scanner.full_scan()
    scanner.generate_reports()
    print("\n" + "="*60)
    print(f"🛑 SCAN COMPLETE: {scanner.results['regex_scan']['total_leaks']} leaks identified.")
    print("="*60)
