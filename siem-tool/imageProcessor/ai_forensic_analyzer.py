#!/usr/bin/env python3
"""
AI Forensic Analyzer
Uses OpenRouter API (free LLMs) to analyze preprocessed forensic artifacts.
Generates smart reports with reasoning.
"""

import os
import re
import json
import time
import argparse
import html
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime
from urllib.request import Request, urlopen
from urllib.error import URLError
import urllib.parse


import requests

class OpenRouterClient:
    """Client for OpenRouter API (free tier supported)."""

    def __init__(self, api_key: str, model: str = "meta-llama/llama-3.1-8b-instruct"):
        self.api_key = api_key
        self.model = model
        self.base_url = "https://openrouter.ai/api/v1"

    def chat(
        self,
        system_prompt: str,
        user_prompt: str,
        max_tokens: int = 4000,
        temperature: float = 0.3,
    ) -> Optional[str]:
        """Send chat request to OpenRouter."""

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "HTTP-Referer": "https://github.com/forensic-tools",
            "X-Title": "AI Forensic Analyzer",
        }

        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "max_tokens": max_tokens,
            "temperature": temperature,
        }

        try:
            response = requests.post(
                f"{self.base_url}/chat/completions",
                json=payload,
                headers=headers,
                timeout=180
            )
            
            if response.status_code != 200:
                print(f"[!] API Error: Status {response.status_code} - {response.text}")
                return None
                
            data = response.json()
            if "choices" in data and len(data["choices"]) > 0:
                return data["choices"][0]["message"]["content"]
            else:
                print(f"[!] Unexpected response: {data}")
                return None

        except Exception as e:
            print(f"[!] Error: {e}")
            return None


class AIForensicAnalyzer:
    def __init__(self, output_dir: str, api_key: str = None, model: str = None):
        self.output_dir = Path(output_dir)

        # Default to free model if not specified
        self.model = model or "meta-llama/llama-3.1-8b-instruct"

        # Try to get API key from environment or parameter
        self.api_key = api_key or os.environ.get("OPENROUTER_API_KEY")

        if not self.api_key:
            print("[!] No API key provided!")
            print("[*] Options:")
            print("    1. Set OPENROUTER_API_KEY environment variable")
            print("    2. Pass --api-key argument")
            print("    3. Get free key from https://openrouter.ai/settings")

        self.client = None
        if self.api_key:
            self.client = OpenRouterClient(self.api_key, self.model)

    def analyze(self, preprocessed_data: Dict = None) -> Dict[str, Any]:
        """Run AI analysis on preprocessed forensic data."""

        if not self.client:
            print("[!] Cannot proceed without API key")
            return {"error": "No API key provided"}

        print(f"[*] Using model: {self.model}")

        # Load or use provided preprocessed data
        if preprocessed_data is None:
            preprocessed_file = self.output_dir / "preprocessed_for_ai.json"
            if preprocessed_file.exists():
                with open(preprocessed_file, "r") as f:
                    preprocessed_data = json.load(f)
            else:
                print("[!] No preprocessed data found. Run ai_preprocessor.py first.")
                return {"error": "No preprocessed data"}

        # Build analysis prompt
        print("[*] Building analysis prompt...")
        prompt = self._build_analysis_prompt(preprocessed_data)

        # Send to AI
        print("[*] Sending to AI for analysis... (this may take a minute)")
        start_time = time.time()

        response = self.client.chat(
            system_prompt=self._get_system_prompt(), user_prompt=prompt
        )

        elapsed = time.time() - start_time
        print(f"[*] Analysis completed in {elapsed:.1f} seconds")

        if not response:
            return {"error": "AI analysis failed"}

        # Parse response
        result = {
            "timestamp": datetime.now().isoformat(),
            "model": self.model,
            "analysis_time_seconds": elapsed,
            "raw_response": response,
            "findings": [],
            "summary": "",
            "risk_level": "UNKNOWN",
        }

        # Try to extract JSON from response
        parsed = self._parse_json_response(response)
        if parsed:
            result.update(parsed)

        return result

    def _get_system_prompt(self) -> str:
        """Get system prompt for the AI."""
        return """You are an expert digital forensic analyst specializing in anti-forensic technique detection.

Your task is to analyze extracted forensic artifacts from a Windows disk image and identify evidence of anti-forensic activities.

COMMON ANTI-FORENSIC TECHNIQUES TO DETECT:

1. TIMESTOMPING
   - Modifying file timestamps (MAC - Modified, Accessed, Created)
   - Tools: timestomp.exe, bulk timestamp changer
   - Signs: Future dates, identical SI and FN timestamps, USN journal mismatch

2. SHADOW COPY DELETION
   - Deleting Volume Shadow Copies to prevent recovery
   - Tools: vssadmin, wmic shadowcopy
   - Signs: Missing System Volume Information, $Extend without VSS

3. ALTERNATE DATA STREAMS (ADS)
   - Hiding data in NTFS alternate streams
   - Tools: streams.exe, custom scripts
   - Signs: Files with :stream notation

4. LOG CLEARING
   - Deleting or tampering with Windows event logs
   - Tools: wevtutil, clearlogs, eventvwr
   - Signs: Missing .evtx files, cleared logs

5. FILE DELETION/WIPING
   - Permanently removing files
   - Tools: cipher /w, sdelete, Eraser
   - Signs: Orphan files, deleted MFT entries, sparse $Extend

6. REGISTRY TAMPERING
   - Deleting user accounts, services, or evidence
   - Tools: reg delete, forensic tool removal
   - Signs: Missing SAM hive, cleaned SECURITY hive

RESPONSE FORMAT:
You MUST respond with valid JSON in this exact format:

{
  "findings": [
    {
      "technique": "timestomping|shadow_deletion|ads|deletion|log_clearing|registry_tampering|other",
      "severity": "LOW|MEDIUM|HIGH|CRITICAL",
      "evidence": "Specific evidence from the artifacts (file names, timestamps, etc)",
      "explanation": "Detailed explanation of WHY this indicates anti-forensic activity vs normal Windows behavior",
      "recommendation": "Specific follow-up investigation steps",
      "confidence": 0.0-1.0
    }
  ],
  "summary": "2-3 sentence overall assessment",
  "risk_level": "LOW|MEDIUM|HIGH|CRITICAL",
  "recommendations": ["List of general recommendations for the investigator"]
}

IMPORTANT:
- Provide reasoning for each finding
- Distinguish between NORMAL Windows behavior and ACTUAL anti-forensic techniques
- Correlate evidence across multiple artifacts when possible
- If no clear anti-forensic activity found, still provide findings with LOW severity"""

    def _build_analysis_prompt(self, preprocessed_data: Dict) -> str:
        """Build analysis prompt from preprocessed data."""

        evidence = preprocessed_data.get("evidence", {})
        stats = preprocessed_data.get("statistics", {})

        # Build evidence summary
        prompt = f"""ANALYZE THE FOLLOWING FORENSIC EVIDENCE
========================================

PREPROCESSING STATISTICS:
- Total files analyzed: {stats.get("total_files_processed", "N/A")}
- Total data size: {stats.get("total_size_mb", "N/A")} MB

EVIDENCE SUMMARY:
=================

1. TIMESTOMPING INDICATORS:
- Future timestamps found: {len(evidence.get("timestomping", {}).get("future_dates", []))}
- Zero timestamps: {len(evidence.get("timestomping", {}).get("zero_timestamps", []))}
- Timeline entries analyzed: {evidence.get("timestomping", {}).get("total_checked", 0)}
- Sample future dates: {evidence.get("timestomping", {}).get("future_dates", [])[:5]}

2. SHADOW COPY STATUS:
- $Extend metadata exists: {evidence.get("shadow_copies", {}).get("extend_exists", False)}
- System Volume Information folder: {evidence.get("shadow_copies", {}).get("system_volume_info", False)}
- Other indicators: {evidence.get("shadow_copies", {}).get("indicators", [])}

3. ALTERNATE DATA STREAMS:
- Total ADS found: {evidence.get("alternate_data_streams", {}).get("total_found", 0)}
- Zone.Identifier (downloaded files): {evidence.get("alternate_data_streams", {}).get("zone_identifier", 0)}
- Sample streams: {evidence.get("alternate_data_streams", {}).get("samples", [])[:5]}

4. FILE DELETION EVIDENCE:
- Orphaned files: {evidence.get("file_deletion", {}).get("orphans", 0)}
- Deleted MFT entries: {evidence.get("file_deletion", {}).get("deleted_entries", 0)}
- Recycle Bin present: {evidence.get("file_deletion", {}).get("recycle_bin", False)}

5. REGISTRY STATUS:
- Hives referenced: {evidence.get("registry", {}).get("hives_found", [])}
- Forensic tool indicators: {evidence.get("registry", {}).get("tool_indicators", [])}

6. LOG FILES:
- Windows Event Logs (.evtx): {evidence.get("logs", {}).get("event_logs", 0)}

Now analyze this evidence and produce your findings in JSON format."""

        return prompt

    def _parse_json_response(self, response: str) -> Optional[Dict]:
        """Parse JSON from AI response."""

        # Try to find JSON in response
        json_match = re.search(r"\{[\s\S]*\}", response)

        if json_match:
            try:
                data = json.loads(json_match.group())
                return data
            except json.JSONDecodeError:
                pass

        # Try to extract just the findings array
        findings_match = re.search(r'"findings"\s*:\s*\[[\s\S]*\]', response)

        if findings_match:
            try:
                # Find complete JSON
                brace_count = 0
                start = response.find("{")
                end = start

                for i, char in enumerate(response[start:], start):
                    if char == "{":
                        brace_count += 1
                    elif char == "}":
                        brace_count -= 1
                        if brace_count == 0:
                            end = i + 1
                            break

                if start >= 0 and end > start:
                    data = json.loads(response[start:end])
                    return data
            except:
                pass

        return None

    def generate_html_report(
        self, analysis_result: Dict, output_file: str = None
    ) -> str:
        """Generate HTML report from analysis results."""

        findings = analysis_result.get("findings", [])
        summary = analysis_result.get("summary", "No summary available.")
        risk_level = analysis_result.get("risk_level", "UNKNOWN")

        # Color coding for severity
        severity_colors = {
            "CRITICAL": "#dc2626",
            "HIGH": "#ea580c",
            "MEDIUM": "#ca8a04",
            "LOW": "#16a34a",
            "UNKNOWN": "#6b7280",
        }

        risk_color = severity_colors.get(risk_level, "#6b7280")

        # Build findings HTML
        findings_html = ""
        for i, finding in enumerate(findings, 1):
            severity = finding.get("severity", "UNKNOWN")
            color = severity_colors.get(severity, "#6b7280")

            findings_html += f"""
            <div class="finding">
                <div class="finding-header">
                    <span class="severity" style="background-color: {color}">{severity}</span>
                    <span class="technique">{finding.get("technique", "Unknown").upper()}</span>
                    <span class="confidence">Confidence: {finding.get("confidence", 0) * 100:.0f}%</span>
                </div>
                <div class="finding-content">
                    <p><strong>Evidence:</strong> {html.escape(str(finding.get("evidence", "N/A")))}</p>
                    <p><strong>Explanation:</strong> {html.escape(str(finding.get("explanation", "N/A")))}</p>
                    <p><strong>Recommendation:</strong> {html.escape(str(finding.get("recommendation", "N/A")))}</p>
                </div>
            </div>
            """

        if not findings_html:
            findings_html = "<p>No findings to display.</p>"

        # Build recommendations
        recommendations = analysis_result.get("recommendations", [])
        rec_html = ""
        for rec in recommendations:
            rec_html += f"<li>{html.escape(str(rec))}</li>"

        if not rec_html:
            rec_html = "<li>No specific recommendations.</li>"

        # HTML template
        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AI Forensic Analysis Report</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            line-height: 1.6;
            background: #f5f5f5;
            color: #333;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }}
        .header {{
            background: linear-gradient(135deg, #1e3a5f 0%, #2d5a87 100%);
            color: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 20px;
        }}
        .header h1 {{
            font-size: 2em;
            margin-bottom: 10px;
        }}
        .meta {{
            opacity: 0.8;
            font-size: 0.9em;
        }}
        .summary-box {{
            background: white;
            padding: 25px;
            border-radius: 10px;
            margin-bottom: 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        .risk-badge {{
            display: inline-block;
            padding: 8px 16px;
            border-radius: 20px;
            color: white;
            font-weight: bold;
            margin-top: 10px;
        }}
        .findings-section {{
            background: white;
            padding: 25px;
            border-radius: 10px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        .finding {{
            border-left: 4px solid #ccc;
            padding: 15px;
            margin-bottom: 15px;
            background: #f9f9f9;
            border-radius: 5px;
        }}
        .finding-header {{
            display: flex;
            align-items: center;
            gap: 15px;
            margin-bottom: 10px;
        }}
        .severity {{
            padding: 4px 12px;
            border-radius: 12px;
            color: white;
            font-size: 0.8em;
            font-weight: bold;
        }}
        .technique {{
            font-weight: bold;
            color: #1e3a5f;
        }}
        .confidence {{
            color: #666;
            font-size: 0.9em;
        }}
        .finding-content p {{
            margin-bottom: 8px;
        }}
        .finding-content strong {{
            color: #1e3a5f;
        }}
        .recommendations {{
            background: white;
            padding: 25px;
            border-radius: 10px;
            margin-top: 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        .recommendations ul {{
            margin-left: 20px;
        }}
        .recommendations li {{
            margin-bottom: 8px;
        }}
        .footer {{
            text-align: center;
            padding: 20px;
            color: #666;
            font-size: 0.9em;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>AI Forensic Analysis Report</h1>
            <div class="meta">
                <p>Generated: {analysis_result.get("timestamp", "N/A")}</p>
                <p>Model: {analysis_result.get("model", "N/A")}</p>
                <p>Analysis Time: {analysis_result.get("analysis_time_seconds", 0):.1f} seconds</p>
            </div>
        </div>
        
        <div class="summary-box">
            <h2>Summary</h2>
            <p>{html.escape(summary)}</p>
            <div class="risk-badge" style="background-color: {risk_color}">
                Risk Level: {risk_level}
            </div>
        </div>
        
        <div class="findings-section">
            <h2>Findings ({len(findings)} total)</h2>
            {findings_html}
        </div>
        
        <div class="recommendations">
            <h2>Recommendations</h2>
            <ul>
                {rec_html}
            </ul>
        </div>
        
        <div class="footer">
            <p>AI Forensic Analyzer - Powered by OpenRouter</p>
        </div>
    </div>
</body>
</html>"""

        if output_file:
            output_path = Path(output_file)
        else:
            output_path = self.output_dir / "ai_forensic_report.html"

        with open(output_path, "w") as f:
            f.write(html_content)

        print(f"[+] HTML report saved to: {output_path}")

        return html_content


def main():
    parser = argparse.ArgumentParser(
        description="AI-Powered Forensic Analysis",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s output_folder --api-key YOUR_KEY
  %(prog)s output_folder -k YOUR_KEY -m "anthropic/claude-3-haiku"
  %(prog)s output_folder --report-only

Get free API key: https://openrouter.ai/settings
Models: https://openrouter.ai/models
        """,
    )
    parser.add_argument("output_dir", help="Directory with forensic artifacts")
    parser.add_argument("-k", "--api-key", help="OpenRouter API key")
    parser.add_argument(
        "-m",
        "--model",
        default="meta-llama/llama-3.1-8b-instruct",
        help="Model to use (default: meta-llama/llama-3.1-8b-instruct)",
    )
    parser.add_argument("-o", "--output", help="Output file for JSON results")
    parser.add_argument("--html", action="store_true", help="Generate HTML report")
    parser.add_argument(
        "--report-only",
        action="store_true",
        help="Generate HTML report only (skip AI analysis)",
    )

    args = parser.parse_args()

    # Check for API key
    api_key = args.api_key or os.environ.get("OPENROUTER_API_KEY")

    if not api_key and not args.report_only:
        print("[!] Error: API key required")
        print("[*] Get free key from https://openrouter.ai/settings")
        print("[*] Then run: export OPENROUTER_API_KEY=your_key")
        return

    # Initialize analyzer
    analyzer = AIForensicAnalyzer(args.output_dir, api_key, args.model)

    if args.report_only:
        # Just generate HTML from existing results
        results_file = Path(args.output_dir) / "ai_analysis_results.json"
        if results_file.exists():
            with open(results_file, "r") as f:
                results = json.load(f)
            analyzer.generate_html_report(results, args.output)
        else:
            print("[!] No existing results found")
        return

    # Run preprocessing first
    print("[*] Running preprocessing...")
    from ai_preprocessor import ForensicPreprocessor

    preprocessor = ForensicPreprocessor(args.output_dir)
    preprocessed = preprocessor.run_full_preprocessing()

    # Run AI analysis
    print("[*] Running AI analysis...")
    results = analyzer.analyze(preprocessed)

    # Save JSON results
    results_file = args.output or str(
        Path(args.output_dir) / "ai_analysis_results.json"
    )
    with open(results_file, "w") as f:
        json.dump(results, f, indent=2, default=str)
    print(f"[+] Results saved to: {results_file}")

    # Generate HTML report
    if args.html or True:  # Always generate HTML
        analyzer.generate_html_report(results)


if __name__ == "__main__":
    main()
