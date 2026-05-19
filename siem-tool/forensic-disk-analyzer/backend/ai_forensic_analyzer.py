#!/usr/bin/env python3
"""
AI Forensic Analyzer (v2)
Uses OpenRouter API for cloud GLM-5 model analysis.
Generates smart reports with deep reasoning and evidence-backed findings.
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


class OpenRouterClient:
    """Client for OpenRouter API and Ollama."""

    def __init__(
        self,
        api_key: str,
        model: str = "glm-5:cloud",
        ollama_url: str = "http://localhost:11434",
    ):
        self.api_key = api_key
        self.model = model
        self.ollama_url = ollama_url
        self.base_url = "https://openrouter.ai/api/v1"

        # Determine if using Ollama (local) or OpenRouter (cloud)
        self.use_ollama = "glm-" in model or "llama" in model.lower()

    def chat(
        self,
        system_prompt: str,
        user_prompt: str,
        max_tokens: int = 4000,
        temperature: float = 0.2,
    ) -> Optional[str]:
        """Send chat request to OpenRouter API or Ollama."""

        if self.use_ollama:
            return self._ollama_chat(
                system_prompt, user_prompt, max_tokens, temperature
            )
        else:
            return self._openrouter_chat(
                system_prompt, user_prompt, max_tokens, temperature
            )

    def _ollama_chat(
        self,
        system_prompt: str,
        user_prompt: str,
        max_tokens: int = 4000,
        temperature: float = 0.2,
    ) -> Optional[str]:
        """Send chat request to Ollama."""

        url = f"{self.ollama_url}/api/chat"
        print(f"[*] Using Ollama API with model: {self.model}")

        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "stream": False,
            "options": {
                "temperature": temperature,
                "num_predict": max_tokens,
            },
        }

        try:
            req = Request(url, data=json.dumps(payload).encode("utf-8"))
            req.add_header("Content-Type", "application/json")

            with urlopen(req, timeout=300) as response:
                result = json.loads(response.read().decode("utf-8"))
                return result.get("message", {}).get("content", "")
        except Exception as e:
            print(f"[!] Ollama API error: {e}")
            return None

    def _openrouter_chat(
        self,
        system_prompt: str,
        user_prompt: str,
        max_tokens: int = 4000,
        temperature: float = 0.2,
    ) -> Optional[str]:
        """Send chat request to OpenRouter API."""

        url = f"{self.base_url}/chat/completions"
        print(f"[*] OpenRouter Request: model={self.model}")

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "HTTP-Referer": "https://siem-tool.local",
            "X-Title": "SIEM Forensic Tool",
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
            req = Request(
                url,
                data=json.dumps(payload).encode("utf-8"),
                headers=headers,
                method="POST",
            )

            print(f"[*] Sending request to model {self.model}... (timeout=300s)")
            with urlopen(req, timeout=300) as response:
                raw_body = response.read().decode("utf-8")
                data = json.loads(raw_body)

                if "choices" in data and len(data["choices"]) > 0:
                    return data["choices"][0]["message"]["content"]
                else:
                    print(
                        f"[!] Unexpected or empty response from OpenRouter: {raw_body}"
                    )
                    return f"ERROR: Empty response from model. Raw body: {raw_body}"

        except URLError as e:
            print(f"[!] OpenRouter API URLError: {e}")
            return f"ERROR: Connection failed to OpenRouter. Error: {e}"
        except Exception as e:
            print(f"[!] General Error in OpenRouterClient: {e}")
            import traceback

            traceback.print_exc()
            return f"ERROR: {str(e)}"


class AIForensicAnalyzer:
    def __init__(
        self,
        output_dir: str,
        api_key: Optional[str] = None,
        model: Optional[str] = None,
        ollama_url: Optional[str] = None,
    ):
        self.output_dir = Path(output_dir)
        self.api_key = api_key or os.environ.get("OPENROUTER_API_KEY", "")
        self.model = model or os.environ.get(
            "OPENROUTER_MODEL", "google/gemini-2.0-flash-001"
        )
        self.ollama_url = ollama_url or os.environ.get(
            "OLLAMA_URL", "http://localhost:11434"
        )
        self.client = OpenRouterClient(self.api_key, self.model, self.ollama_url)

    def analyze(self, preprocessed_data: Optional[Dict] = None) -> Dict[str, Any]:
        """Run AI analysis using OpenRouter GLM model."""

        print(f"[*] Using OpenRouter API with model: {self.model}")

        if preprocessed_data is None:
            preprocessed_file = self.output_dir / "preprocessed_for_ai.json"
            if preprocessed_file.exists():
                with open(preprocessed_file, "r") as f:
                    preprocessed_data = json.load(f)
            else:
                print("[!] No preprocessed data found.")
                return {"error": "No preprocessed data"}

        context = preprocessed_data.get("context", {})  # type: ignore
        system_prompt = context.get("system_prompt", "You are a forensic expert.")
        evidence_summary = context.get("evidence_summary", "No evidence summary.")
        instructions = context.get("instructions", "Analyze evidence.")

        user_prompt = f"""You are analyzing a disk forensic image. Below is the evidence summary from multiple detection layers.

{evidence_summary}

INSTRUCTIONS:
{instructions}

RESPONSE GUIDELINES:
1. Provide a detailed forensic analysis of the evidence.
2. Identify the most suspicious files and explain WHY they are flagged.
3. At the end of your response, you MUST provide a JSON block containing the structured findings.

The JSON block should look like this:
```json
{{
  "findings": [
    {{
      "technique": "timestomping",
      "severity": "CRITICAL",
      "evidence": "File suspicious.exe created before USN entry",
      "explanation": "Temporal causality violation...",
      "recommendation": "Check for script activity",
      "confidence": 0.95
    }}
  ],
  "summary": "Overall summary of the case.",
  "risk_level": "CRITICAL",
  "recommendations": ["Action 1", "Action 2"]
}}
```"""

        print("[*] Sending request to GLM model via OpenRouter...")

        start_time = time.time()
        response = self.client.chat(system_prompt, user_prompt, max_tokens=8000)

        elapsed = time.time() - start_time
        print(f"[*] Analysis complete in {elapsed:.1f}s")

        if not response:
            return {
                "error": "AI response was empty. Check if OpenRouter API key is valid.",
                "status": "failed",
                "timestamp": datetime.now().isoformat(),
            }

        # Parse JSON from response
        result = {
            "timestamp": datetime.now().isoformat(),
            "model": self.model,
            "analysis_time_seconds": elapsed,
            "raw_response": response,
        }

        parsed = self._parse_json(response)
        if parsed:
            result.update(parsed)
        else:
            print("[!] Failed to parse JSON from AI response.")
            result["error"] = "JSON parsing failed"

        return result

    def _parse_json(self, response: str) -> Optional[Dict]:
        """Robustly extract JSON from the model response, even if surrounded by text/markdown."""
        if not response:
            return None

        # Clean the response of potential artifacts
        response = response.strip()

        # 1. Try to find JSON block in markdown
        json_match = re.search(r"```json\s*(\{.*?\})\s*```", response, re.DOTALL)
        if json_match:
            try:
                return json.loads(json_match.group(1))
            except:
                pass

        # 2. Try to find the largest bracketed structure
        try:
            # Find the first { and the last }
            first = response.find("{")
            last = response.rfind("}")
            if first != -1 and last != -1:
                potential_json = response[first : last + 1]
                return json.loads(potential_json)
        except:
            pass

        # 3. Last resort: simple direct parse
        try:
            return json.loads(response)
        except:
            return None

    def generate_html_report(self, analysis_result: Dict) -> str:
        """Generate the final report section for the frontend."""
        findings = analysis_result.get("findings", [])
        risk_level = analysis_result.get("risk_level", "UNKNOWN")
        summary = analysis_result.get("summary", "No summary provided.")

        # Mapping severity to colors
        colors = {
            "CRITICAL": "danger",
            "HIGH": "warning",
            "MEDIUM": "info",
            "LOW": "success",
        }

        html_output = f"""
        <div class="ai-report-container p-4">
            <h3 class="text-primary mb-4"><i class="fas fa-robot me-2"></i>AI Forensic Intelligence Analysis (GLM-5)</h3>
            
            <div class="alert alert-{colors.get(risk_level, "secondary")} mb-4">
                <h4 class="alert-heading">Overall Risk: {risk_level}</h4>
                <p class="mb-0">{summary}</p>
            </div>

            <div class="row">
        """

        for fnd in findings:
            sev = fnd.get("severity", "LOW")
            html_output += f"""
                <div class="col-md-6 mb-3">
                    <div class="card h-100 border-start border-4 border-{colors.get(sev, "info")}">
                        <div class="card-body">
                            <h5 class="card-title text-uppercase font-weight-bold" style="font-size: 0.9rem;">
                                {fnd.get("technique", "Detection")}
                            </h5>
                            <p class="card-text"><strong>Evidence:</strong> {html.escape(fnd.get("evidence", ""))}</p>
                            <p class="card-text text-muted" style="font-size: 0.85rem;">{html.escape(fnd.get("explanation", ""))}</p>
                            <div class="mt-2">
                                <span class="badge bg-{colors.get(sev, "info")}">{sev}</span>
                                <span class="ms-2 text-primary" style="font-size: 0.8rem;">Confidence: {int(fnd.get("confidence", 0) * 100)}%</span>
                            </div>
                        </div>
                    </div>
                </div>
            """

        html_output += "</div></div>"

        report_path = self.output_dir / "live_tampering_report.html"
        with open(report_path, "w") as f:
            f.write(html_output)

        return html_output


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("output_dir")
    parser.add_argument("--api-key", default=None, help="OpenRouter API key")
    parser.add_argument("--model", default="google/gemini-2.0-flash-001")
    args = parser.parse_args()

    api_key = args.api_key or os.environ.get("OPENROUTER_API_KEY")
    if not api_key:
        print(
            "Error: OpenRouter API key required. Set OPENROUTER_API_KEY or use --api-key"
        )
        exit(1)

    analyzer = AIForensicAnalyzer(args.output_dir, api_key, args.model)
    results = analyzer.analyze()
    analyzer.generate_html_report(results)
