#!/usr/bin/env python3
"""BugFinder - Analisi euristica di bug e codice AI-like.

Versione migliorata a partire dal codice originale dell'utente.
Obiettivo: rimanere semplice ma più robusto, configurabile e usabile.
"""

import os
import re
import sys
import json
import argparse
import multiprocessing
from collections import defaultdict
from concurrent.futures import ProcessPoolExecutor, as_completed
import hashlib
from typing import Dict, List, Any, Optional, Tuple


class BugFinder:
    """Analizzatore di codice per pattern di bug comuni e indicatori di AI.

    Tutte le analisi sono euristiche: i risultati vanno sempre verificati
    manualmente. Serve come "radar" veloce, non come prova definitiva.
    """

    # Severità base per ciascun tipo di bug
    SEVERITY: Dict[str, str] = {
        "memory_leak": "high",
        "null_pointer": "high",
        "buffer_overflow": "high",
        "division_by_zero": "high",
        "integer_overflow": "high",
        "sql_injection": "critical",
        "resource_leak": "medium",
        "race_condition": "high",
        "infinite_loop": "medium",
        "exception_swallow": "medium",
        "format_string": "medium",
        "uninitialized_var": "medium",
        # Python
        "except_all": "medium",
        "mutable_default": "medium",
        "global_var": "low",
        "eval_usage": "high",
        "shell_injection": "high",
        "duplicate_keys": "low",
        # JS
        "triple_equals": "low",
        "global_leak": "medium",
        "promise_no_catch": "medium",
        "alert_debug": "low",
    }

    def __init__(self) -> None:
        # Pattern generici (C/C++/altri linguaggi C-like)
        self.bug_patterns: Dict[str, Tuple[str, str]] = {
            "memory_leak": (
                r"\b(?:malloc|calloc|realloc)\s*\([^;]*\)(?![^;]*(?:free|delete))",
                "Possibile memory leak: allocazione di memoria senza free/delete corrispondente",
            ),
            "null_pointer": (
                r"\b\w+\s*=\s*NULL\s*;[^\n]*\n[^\n]*\b\w+\s*->",
                "Possibile dereferenziazione di puntatore NULL",
            ),
            "buffer_overflow": (
                r"\b(strcpy|strcat|gets)\s*\(",
                "Rischio di buffer overflow: usa strncpy, strncat o fgets",
            ),
            "uninitialized_var": (
                r"\b(?:int|char|short|long|float|double)\s+(\w+)\s*;",
                "Variabile potenzialmente non inizializzata",
            ),
            "division_by_zero": (
                r"/\s*0\b",
                "Possibile divisione per zero",
            ),
            "integer_overflow": (
                r"\b(?:int|short|long)\s+\w+\s*=\s*(?:INT_MAX|SHRT_MAX|LONG_MAX)\s*(?:\+|\+\+)",
                "Rischio di integer overflow",
            ),
            "format_string": (
                r"\bprintf\s*\(\s*\w+\s*\)",
                "Vulnerabilità format string: usa printf(\"%s\", var)",
            ),
            "resource_leak": (
                r"\b(?:fopen|open|socket)\s*\([^;]*\)(?![^;]*(?:fclose|close))",
                "Possibile resource leak: risorsa aperta senza close corrispondente",
            ),
            "race_condition": (
                r"(?:pthread_create|std::thread)[^;]*(?:shared|global)",
                "Potenziale race condition su variabile condivisa",
            ),
            "sql_injection": (
                r"(?:execute|query)\s*\([^)]*\+[^)]*\)",
                "Possibile SQL injection: usa query parametrizzate",
            ),
            "infinite_loop": (
                r"\bwhile\s*\(\s*(?:1|true)\s*\)\s*{(?:(?!break).)*}",
                "Loop infinito potenziale: nessun break trovato nel corpo",
            ),
            "exception_swallow": (
                r"try\s*{[^}]*}\s*catch\s*\([^)]*\)\s*{\s*}",
                "Eccezione catturata ma non gestita",
            ),
        }

        # Pattern specifici Python
        self.python_patterns: Dict[str, Tuple[str, str]] = {
            "except_all": (
                r"\bexcept\s*:",
                "Evita 'except:' generico, specifica le eccezioni da catturare",
            ),
            "mutable_default": (
                r"\bdef\s+\w+\s*\([^)]*=\s*(?:\[\]|{}|\(\))",
                "Parametro di default mutabile, può causare comportamenti inattesi",
            ),
            "global_var": (
                r"\bglobal\s+\w+",
                "Uso di variabile globale può causare effetti collaterali indesiderati",
            ),
            "eval_usage": (
                r"\beval\s*\(",
                "Uso di eval() è potenzialmente pericoloso",
            ),
            "shell_injection": (
                r"os\.system\s*\([^)]*\+[^)]*\)|subprocess\.(?:call|run)\s*\([^)]*shell\s*=\s*True[^)]*\+[^)]*\)",
                "Possibile iniezione di comandi shell",
            ),
            "duplicate_keys": (
                r"{[^}]*\b(\w+)\s*:\s*[^,}]+,[^}]*\b\1\s*:\s*[^,}]+[^}]*}",
                "Possibili chiavi duplicate nei dizionari",
            ),
        }

        # Pattern specifici JavaScript/TypeScript
        self.js_patterns: Dict[str, Tuple[str, str]] = {
            "triple_equals": (
                r"(?<![=!])==(?![=])|!=(?![=])",
                "Usa === e !== invece di == e != per evitare coercizioni di tipo",
            ),
            "global_leak": (
                r"(?<!\bvar\b|\blet\b|\bconst\b)\s+\w+\s*=",
                "Possibile leak di variabile globale, usa var/let/const",
            ),
            "promise_no_catch": (
                r"\.then\s*\([^)]*\)(?!\s*\.catch)",
                "Promise senza .catch() per gestire errori",
            ),
            "alert_debug": (
                r"\balert\s*\(",
                "Alert trovato, rimuovi prima della produzione",
            ),
            "eval_usage": (
                r"\beval\s*\(",
                "Uso di eval() è potenzialmente pericoloso",
            ),
        }

        # Pattern per rilevare codice generato da AI
        self.ai_indicators: Dict[str, List[str]] = {
            "claude_signature": [
                r"(?i)generated\s+(?:by|with)\s+(?:claude|anthropic)",
                r"(?i)created\s+(?:by|with)\s+(?:claude|anthropic)",
                r"(?i)autore:\s*claude",
                r"(?i)author:\s*claude",
            ],
            "chatgpt_signature": [
                r"(?i)generated\s+(?:by|with)\s+(?:chatgpt|openai|gpt-[0-9])",
                r"(?i)created\s+(?:by|with)\s+(?:chatgpt|openai)",
                r"(?i)copyright.*openai",
            ],
            "generic_ai": [
                r"(?i)ai[\s-]generated",
                r"(?i)generated\s+(?:by|using)\s+(?:artificial\s+intelligence|AI)",
                r"(?i)this\s+code\s+was\s+(?:auto-generated|automatically\s+generated)",
            ],
            "common_ai_patterns": [
                r"#\s*Example\s+usage:",
                r"#\s*Note:",
                r'(?:"""|\'\'\')[\s\S]*?(?:Example|Usage|Parameters|Returns)[\s\S]*?(?:"""|\'\'\')',
                r"def\s+\w+\s*\([^)]*\)\s*->\s*(?:int|str|bool|float|list|dict|None)",
            ],
        }

        # Pattern stilistici AI
        self.ai_style_patterns: List[str] = [
            r"(?:if|elif|else).*:\s*#.*",
            r"try:\s*\n(?:\s+.+\n)*\s*except.*:\s*#\s*Handle",
            r"\b(?:TODO|FIXME|NOTE|HACK):",
        ]

        # Cache in memoria per hash dei file (evita rianalisi identiche)
        self._hash_cache: Dict[str, Dict[str, Any]] = {}

    # ---------------- AI DETECTION ---------------- #

    def detect_ai_generation(self, content: str, file_path: str) -> Dict[str, Any]:
        """Rileva se il codice è probabilmente generato da AI (euristico)."""
        ai_signals: Dict[str, Any] = {
            "confidence": 0,
            "indicators": [],
            "ai_type": None,
            "file": file_path,
        }

        # Firme esplicite
        for ai_type, patterns in self.ai_indicators.items():
            for pattern in patterns:
                if re.search(pattern, content, re.IGNORECASE | re.MULTILINE):
                    ai_signals["indicators"].append(f"Firma esplicita: {ai_type}")
                    ai_signals["confidence"] += 40
                    if not ai_signals["ai_type"]:
                        ai_signals["ai_type"] = ai_type
                    break

        # Pattern stilistici
        style_matches = 0
        for pattern in self.ai_style_patterns:
            style_matches += len(re.findall(pattern, content, re.MULTILINE))

        if style_matches >= 3:
            ai_signals["indicators"].append(
                f"Pattern stilistici AI: {style_matches} corrispondenze"
            )
            ai_signals["confidence"] += min(style_matches * 3, 30)

        # Densità commenti
        lines = content.splitlines()
        code_lines = [l for l in lines if l.strip() and not l.lstrip().startswith("#")]
        comment_lines = [l for l in lines if l.lstrip().startswith("#")]
        if code_lines:
            comment_ratio = len(comment_lines) / len(code_lines)
            if comment_ratio > 0.3:
                ai_signals["indicators"].append(
                    f"Alta densità di commenti: {comment_ratio:.1%}"
                )
                ai_signals["confidence"] += 10

        # Docstring lunghe
        docstring_pattern = r'(?:"""|\'\'\')[\s\S]{100,}?(?:"""|\'\'\')'
        docstrings = re.findall(docstring_pattern, content)
        if len(docstrings) >= 2:
            ai_signals["indicators"].append(
                f"Docstring dettagliate: {len(docstrings)} trovate"
            )
            ai_signals["confidence"] += 10

        ai_signals["confidence"] = min(ai_signals["confidence"], 100)
        return ai_signals

    # ---------------- ANALISI FILE ---------------- #

    def _select_patterns_for_extension(
        self, file_ext: str
    ) -> Dict[str, Tuple[str, str]]:
        if file_ext == ".py":
            return {**self.bug_patterns, **self.python_patterns}
        if file_ext in (".js", ".ts", ".jsx", ".tsx"):
            return {**self.bug_patterns, **self.js_patterns}
        return self.bug_patterns

    def analyze_file(self, file_path: str) -> Dict[str, Any]:
        """Analizza un file alla ricerca di bug pattern e indicatori AI."""
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
        except Exception as e:
            print(f"Errore nel leggere il file {file_path}: {e}")
            return {"issues": [], "ai_detection": None, "file_hash": None}

        file_hash = hashlib.md5(content.encode("utf-8", errors="ignore")).hexdigest()
        if file_hash in self._hash_cache:
            cached = self._hash_cache[file_hash].copy()
            for issue in cached["issues"]:
                issue["file"] = file_path
            if cached["ai_detection"]:
                cached["ai_detection"]["file"] = file_path
            return cached

        file_ext = os.path.splitext(file_path)[1].lower()
        issues: List[Dict[str, Any]] = []

        ai_detection = self.detect_ai_generation(content, file_path)
        all_patterns = self._select_patterns_for_extension(file_ext)

        compiled = [
            (bug_type, re.compile(pat, re.MULTILINE | re.DOTALL), desc)
            for bug_type, (pat, desc) in all_patterns.items()
        ]

        content_lines = content.splitlines()
        for bug_type, regex, desc in compiled:
            for match in regex.finditer(content):
                line_num = content[: match.start()].count("\n") + 1
                line_content = (
                    content_lines[line_num - 1].strip()
                    if 0 < line_num <= len(content_lines)
                    else ""
                )
                issues.append(
                    {
                        "file": file_path,
                        "line": line_num,
                        "type": bug_type,
                        "severity": self.SEVERITY.get(bug_type, "medium"),
                        "description": desc,
                        "code": line_content,
                    }
                )

        result = {"issues": issues, "ai_detection": ai_detection, "file_hash": file_hash}
        self._hash_cache[file_hash] = result
        return result

    # ---------------- ANALISI DIRECTORY ---------------- #

    def _iter_source_files(
        self, directory_path: str, extensions: List[str], excluded_dirs: List[str]
    ):
        exts = {e.lower() for e in extensions}
        excluded = set(excluded_dirs)
        for root, dirs, files in os.walk(directory_path):
            dirs[:] = [d for d in dirs if d not in excluded]
            for name in files:
                if any(name.lower().endswith(ext) for ext in exts):
                    yield os.path.join(root, name)

    def analyze_directory(
        self,
        directory_path: str,
        extensions: Optional[List[str]] = None,
        excluded_dirs: Optional[List[str]] = None,
        max_workers: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        if extensions is None:
            extensions = [
                ".c",
                ".cpp",
                ".h",
                ".hpp",
                ".py",
                ".js",
                ".java",
                ".php",
            ]
        if excluded_dirs is None:
            excluded_dirs = ["node_modules", "venv", "__pycache__", ".git", "build", "dist"]
        if max_workers is None or max_workers <= 0:
            max_workers = max(1, multiprocessing.cpu_count() - 1)

        files = list(self._iter_source_files(directory_path, extensions, excluded_dirs))
        if not files:
            print("Nessun file da analizzare per le estensioni specificate.")
            return []

        print(f"Analisi di {len(files)} file con {max_workers} worker paralleli...")

        def _worker(path: str) -> Dict[str, Any]:
            local = BugFinder()
            return local.analyze_file(path)

        results: List[Dict[str, Any]] = []
        with ProcessPoolExecutor(max_workers=max_workers) as executor:
            future_to_file = {executor.submit(_worker, p): p for p in files}
            completed = 0
            total = len(files)
            for fut in as_completed(future_to_file):
                completed += 1
                if completed % 10 == 0 or completed == total:
                    print(f"Progresso: {completed}/{total} file analizzati", end="\r")
                try:
                    results.append(fut.result())
                except Exception as e:
                    path = future_to_file[fut]
                    print(f"\nErrore nell'analisi di {path}: {e}")
        print()
        return results

    # ---------------- REPORTING ---------------- #

    def _sort_issues(self, issues: List[Dict[str, Any]], sort_by: str) -> List[Dict[str, Any]]:
        if sort_by == "line":
            return sorted(issues, key=lambda x: (x["file"], x["line"]))
        if sort_by == "type":
            return sorted(issues, key=lambda x: (x["type"], x["file"], x["line"]))
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        return sorted(
            issues,
            key=lambda x: (order.get(x.get("severity", "medium"), 3), x["file"], x["line"]),
        )

    def generate_report(
        self,
        results: List[Dict[str, Any]],
        output_format: str = "console",
        sort_by: str = "severity",
        min_severity: str = "low",
    ) -> None:
        all_issues: List[Dict[str, Any]] = []
        ai_files: List[Dict[str, Any]] = []

        sev_order = {"low": 3, "medium": 2, "high": 1, "critical": 0}
        min_rank = sev_order.get(min_severity, 3)

        for res in results or []:
            issues = res.get("issues") or []
            for issue in issues:
                rank = sev_order.get(issue.get("severity", "medium"), 3)
                if rank <= min_rank:
                    all_issues.append(issue)

            ai = res.get("ai_detection")
            if ai and ai.get("confidence", 0) > 30:
                ai_files.append(
                    {
                        "file": ai.get("file")
                        or (issues[0]["file"] if issues else "Unknown"),
                        "confidence": ai["confidence"],
                        "indicators": ai["indicators"],
                        "ai_type": ai["ai_type"],
                    }
                )

        if output_format == "console":
            self._report_console(all_issues, ai_files, sort_by)
        elif output_format == "html":
            self._generate_html_report(all_issues, ai_files)
        elif output_format == "json":
            self._generate_json_report(all_issues, ai_files)
        else:
            print(f"Formato di output non supportato: {output_format}")

    def _report_console(
        self,
        all_issues: List[Dict[str, Any]],
        ai_files: List[Dict[str, Any]],
        sort_by: str,
    ) -> None:
        if ai_files:
            print("\n" + "=" * 80)
            print("RILEVAMENTO CODICE POTENZIALMENTE GENERATO DA AI")
            print("=" * 80)
            for ai in sorted(ai_files, key=lambda x: x["confidence"], reverse=True):
                print(f"\n{ai['file']}")
                print(f"  Confidenza: {ai['confidence']}%")
                if ai["ai_type"]:
                    print(f"  Tipo AI rilevato: {ai['ai_type']}")
                print("  Indicatori:")
                for ind in ai["indicators"]:
                    print(f"    • {ind}")

        if not all_issues:
            print("\nNessun potenziale bug trovato con i filtri attuali.")
            return

        print("\n" + "=" * 80)
        print("ANALISI BUG")
        print("=" * 80)

        issues_by_file: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        for issue in self._sort_issues(all_issues, sort_by):
            issues_by_file[issue["file"]].append(issue)

        for file, file_issues in issues_by_file.items():
            print(f"\n{file}")
            print("-" * len(file))
            for issue in file_issues:
                sev = issue.get("severity", "medium").upper()
                print(f"  Linea {issue['line']} [{sev}] {issue['type']}")
                print(f"    {issue['description']}")
                print(f"    Codice: {issue['code']}\n")

        print("\nStatistiche:")
        print(f"   • Totale bug trovati (dopo filtri): {len(all_issues)}")
        print(f"   • File con bug: {len(issues_by_file)}")
        print(f"   • File con indicatori AI: {len(ai_files)}")
        print("   • Nota: risultati euristici, verificare sempre manualmente.")

    def _generate_html_report(
        self, all_issues: List[Dict[str, Any]], ai_files: List[Dict[str, Any]]
    ) -> None:
        html = """<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8" />
  <title>BugFinder Report</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
    h1 { color: #333; }
    .section { background: white; padding: 20px; margin: 20px 0; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
    .ai-section { border-left: 4px solid #9b59b6; }
    .bug-section { border-left: 4px solid #e74c3c; }
    .file { margin-top: 20px; border-bottom: 1px solid #ccc; padding-bottom: 5px; }
    .issue { margin: 10px 0; padding: 10px; background: #f8f8f8; border-left: 4px solid #e74c3c; }
    .ai-file { margin: 10px 0; padding: 10px; background: #f8f8f8; border-left: 4px solid #9b59b6; }
    .confidence { font-weight: bold; color: #f39c12; }
    .issue-type { color: #e74c3c; font-weight: bold; }
    .issue-desc { color: #333; }
    .code { background: #f1c40f; padding: 2px 5px; font-family: monospace; }
    .stats { background: #3498db; color: white; padding: 15px; border-radius: 8px; }
    .disclaimer { font-size: 0.9em; color: #555; margin-top: 10px; }
  </style>
</head>
<body>
  <h1>BugFinder Report</h1>
"""

        if ai_files:
            html += '<div class="section ai-section"><h2>Codice Potenzialmente Generato da AI</h2>'
            for ai in ai_files:
                html += f"""
    <div class="ai-file">
      <h3>{ai['file']}</h3>
      <p class="confidence">Confidenza: {ai['confidence']}%</p>
      <p>Tipo AI: {ai['ai_type'] or 'Generico'}</p>
      <ul>
        {''.join(f'<li>{ind}</li>' for ind in ai['indicators'])}
      </ul>
    </div>
"""
            html += "</div>"

        if all_issues:
            html += '<div class="section bug-section"><h2>Bug Rilevati</h2>'
            by_file: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
            for iss in all_issues:
                by_file[iss["file"]].append(iss)

            for file, file_issues in by_file.items():
                html += f'<div class="file"><h3>{file}</h3>'
                for iss in sorted(file_issues, key=lambda x: x["line"]):
                    html += f"""
      <div class="issue">
        <p>Linea {iss['line']}: <span class="issue-type">{iss['type']} [{iss.get('severity','medium').upper()}]</span></p>
        <p class="issue-desc">{iss['description']}</p>
        <p>Codice: <span class="code">{iss['code']}</span></p>
      </div>
"""
                html += "</div>"
            html += "</div>"

        html += f"""
  <div class="stats">
    <h2>Statistiche</h2>
    <p>• Totale bug trovati: {len(all_issues)}</p>
    <p>• File con bug: {len(set(i['file'] for i in all_issues)) if all_issues else 0}</p>
    <p>• File con indicatori AI: {len(ai_files)}</p>
  </div>
  <div class="disclaimer">
    <strong>Nota:</strong> BugFinder usa pattern euristici basati su regex. I risultati
    possono contenere falsi positivi e falsi negativi. Usa questo report come
    supporto alla revisione manuale, non come prova definitiva.
  </div>
</body>
</html>
"""

        with open("bugfinder_report.html", "w", encoding="utf-8") as f:
            f.write(html)
        print("Report HTML salvato come bugfinder_report.html")

    def _generate_json_report(
        self, all_issues: List[Dict[str, Any]], ai_files: List[Dict[str, Any]]
    ) -> None:
        report = {
            "bugs": all_issues,
            "ai_generated_files": ai_files,
            "statistics": {
                "total_bugs": len(all_issues),
                "files_with_bugs": len(set(i["file"] for i in all_issues)) if all_issues else 0,
                "ai_generated_count": len(ai_files),
            },
            "disclaimer": "Analisi euristica basata su pattern; verificare sempre manualmente.",
        }
        with open("bugfinder_report.json", "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        print("Report JSON salvato come bugfinder_report.json")


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "BugFinder - Strumento per identificare potenziali bug nel codice "
            "e rilevare codice generato da AI (euristico)"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("path", help="Percorso del file o della directory da analizzare")
    parser.add_argument(
        "-e",
        "--extensions",
        nargs="+",
        default=[".c", ".cpp", ".h", ".hpp", ".py", ".js", ".java", ".php"],
        help="Estensioni di file da analizzare (es: .py .js .c)",
    )
    parser.add_argument(
        "-f",
        "--format",
        choices=["console", "html", "json"],
        default="console",
        help="Formato del report di output",
    )
    parser.add_argument(
        "-x",
        "--exclude",
        nargs="+",
        default=["node_modules", "venv", "__pycache__", ".git", "build", "dist"],
        help="Directory da escludere",
    )
    parser.add_argument(
        "-w",
        "--workers",
        type=int,
        default=None,
        help="Numero di worker paralleli (default: CPU count - 1)",
    )
    parser.add_argument(
        "--sort-by",
        choices=["severity", "line", "type"],
        default="severity",
        help="Criterio di ordinamento dei bug nel report console",
    )
    parser.add_argument(
        "--min-severity",
        choices=["low", "medium", "high", "critical"],
        default="low",
        help="Filtra i bug mostrando solo quelli con severità >= selezionata",
    )

    args = parser.parse_args(argv)

    path = os.path.abspath(args.path)
    if not os.path.exists(path):
        print(f"Errore: Il percorso '{path}' non esiste")
        return 1

    bf = BugFinder()
    if os.path.isfile(path):
        results = [bf.analyze_file(path)]
    else:
        results = bf.analyze_directory(path, args.extensions, args.exclude, args.workers)

    bf.generate_report(results, args.format, sort_by=args.sort_by, min_severity=args.min_severity)
    return 0


if __name__ == "__main__":
    multiprocessing.freeze_support()  # necessario su Windows per multiprocessing
    sys.exit(main())
