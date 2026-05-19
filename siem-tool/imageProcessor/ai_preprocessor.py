#!/usr/bin/env python3
"""
AI Forensic Preprocessor
Preprocesses extracted forensic artifacts for AI analysis.
Handles chunking, evidence extraction, and context building.
"""

import os
import re
import json
import hashlib
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime
from collections import defaultdict


class ForensicPreprocessor:
    def __init__(self, output_dir: str):
        self.output_dir = Path(output_dir)
        self.max_tokens = 8000
        self.avg_chars_per_token = 4

        self.file_classification = {"critical": [], "important": [], "standard": []}

    def run_full_preprocessing(self) -> Dict[str, Any]:
        """Run complete preprocessing pipeline."""
        print("[*] Starting preprocessing pipeline...")

        result = {
            "timestamp": datetime.now().isoformat(),
            "output_dir": str(self.output_dir),
            "file_analysis": {},
            "evidence": {},
            "context": {},
            "statistics": {},
        }

        # Step 1: Discover and classify files
        print("[*] Step 1: Classifying output files...")
        self._classify_files()

        # Step 2: Analyze each file type
        print("[*] Step 2: Analyzing files...")
        result["file_analysis"] = self._analyze_all_files()

        # Step 3: Extract evidence features
        print("[*] Step 3: Extracting evidence...")
        result["evidence"] = self._extract_evidence()

        # Step 4: Build AI context
        print("[*] Step 4: Building AI context...")
        result["context"] = self._build_context()

        # Step 5: Calculate statistics
        print("[*] Step 5: Calculating statistics...")
        result["statistics"] = self._calculate_stats()

        # Save preprocessed data
        output_file = self.output_dir / "preprocessed_for_ai.json"
        with open(output_file, "w") as f:
            json.dump(result, f, indent=2, default=str)
        print(f"[+] Preprocessed data saved to: {output_file}")

        return result

    def _classify_files(self):
        """Classify output files by forensic importance."""
        priority_mapping = {
            "usn_journal": "critical",
            "shadow_copies": "critical",
            "registry": "critical",
            "mft": "important",
            "timeline": "important",
            "timestomp": "important",
            "hidden_structures": "important",
            "logs": "standard",
        }

        for file in self.output_dir.glob("*.txt"):
            name = file.name
            size = file.stat().st_size

            category = "standard"
            for key, priority in priority_mapping.items():
                if key in name:
                    category = priority
                    break

            file_info = {
                "path": str(file),
                "name": name,
                "size_bytes": size,
                "size_mb": round(size / (1024 * 1024), 2),
                "priority": category,
            }

            self.file_classification[category].append(file_info)

        logs_dir = self.output_dir / "logs"
        if logs_dir.exists():
            for file in logs_dir.glob("**/*.json"):
                if file.suffix == ".json" and ".evtx." in file.name:
                    file_info = {
                        "path": str(file),
                        "name": file.name,
                        "size_bytes": file.stat().st_size,
                        "size_mb": round(file.stat().st_size / (1024 * 1024), 2),
                        "priority": "important",
                    }
                    self.file_classification["important"].append(file_info)

    def _analyze_all_files(self) -> Dict[str, Any]:
        """Analyze all classified files."""
        analysis = {
            "files_by_priority": self.file_classification,
            "files_analyzed": {},
            "total_files": 0,
        }

        for category, files in self.file_classification.items():
            analysis["files_analyzed"][category] = []

            for file_info in files:
                file_path = Path(file_info["path"])
                file_analysis = self._analyze_file(file_path, category)
                analysis["files_analyzed"][category].append(file_analysis)
                analysis["total_files"] += 1

        return analysis

    def _analyze_file(self, file_path: Path, priority: str) -> Dict[str, Any]:
        """Analyze a single file."""
        analysis = {
            "name": file_path.name,
            "path": str(file_path),
            "size": file_path.stat().st_size,
            "line_count": 0,
            "key_findings": [],
            "suspicious_patterns": [],
            "sample_lines": [],
        }

        try:
            with open(file_path, "r", errors="ignore") as f:
                content = f.read()
                lines = content.split("\n")
                analysis["line_count"] = len(lines)

                # Extract key findings based on file type
                if "usn_journal" in file_path.name:
                    analysis["key_findings"] = self._analyze_usn_journal(content)
                elif "registry" in file_path.name:
                    analysis["key_findings"] = self._analyze_registry(content)
                elif "shadow" in file_path.name:
                    analysis["key_findings"] = self._analyze_shadow_copies(content)
                elif "timeline" in file_path.name or "timestomp" in file_path.name:
                    analysis["key_findings"] = self._analyze_timeline(content)
                elif "mft" in file_path.name:
                    analysis["key_findings"] = self._analyze_mft(content)
                elif "logs" in file_path.name:
                    analysis["key_findings"] = self._analyze_logs(content)
                elif "hidden" in file_path.name:
                    analysis["key_findings"] = self._analyze_ads(content)

                # Get sample lines (first 20 and any suspicious)
                analysis["sample_lines"] = lines[:20]

        except Exception as e:
            analysis["error"] = str(e)

        return analysis

    def _analyze_usn_journal(self, content: str) -> List[Dict]:
        """Analyze USN journal for indicators."""
        findings = []

        if "No USN journal" in content:
            findings.append(
                {
                    "type": "missing",
                    "description": "USN journal not found",
                    "severity": "high",
                }
            )

        # Count entries
        lines = content.split("\n")
        total_entries = len([l for l in lines if l.strip() and not l.startswith("=")])

        findings.append(
            {
                "type": "entry_count",
                "description": f"USN journal contains {total_entries} entries",
                "severity": "info",
            }
        )

        return findings

    def _analyze_registry(self, content: str) -> List[Dict]:
        """Analyze registry files for indicators."""
        findings = []

        # Count registry hives
        patterns = {
            "SAM": r"SAM",
            "SECURITY": r"SECURITY",
            "SOFTWARE": r"SOFTWARE",
            "SYSTEM": r"SYSTEM",
            "NTUSER": r"NTUSER\.DAT",
            "USRCLASS": r"UsrClass\.dat",
        }

        for hive, pattern in patterns.items():
            count = len(re.findall(pattern, content, re.IGNORECASE))
            if count > 0:
                findings.append(
                    {
                        "type": "hive_found",
                        "description": f"{hive}: {count} references",
                        "severity": "info",
                    }
                )

        # Check for tool indicators
        tools = ["ccleaner", "bleachbit", "eraser", "wiper", "evidence"]
        for tool in tools:
            if tool.lower() in content.lower():
                findings.append(
                    {
                        "type": "tool_indicator",
                        "description": f"Possible forensic tool: {tool}",
                        "severity": "high",
                    }
                )

        return findings

    def _analyze_shadow_copies(self, content: str) -> List[Dict]:
        """Analyze shadow copy indicators."""
        findings = []

        if "$Extend" in content:
            findings.append(
                {
                    "type": "extend_found",
                    "description": "$Extend metadata folder found",
                    "severity": "info",
                }
            )

        if "System Volume Information" in content:
            findings.append(
                {
                    "type": "vss_folder_found",
                    "description": "System Volume Information folder exists",
                    "severity": "info",
                }
            )
        elif "No shadow copy" in content:
            findings.append(
                {
                    "type": "no_shadow_copies",
                    "description": "No shadow copy indicators found",
                    "severity": "medium",
                }
            )

        # Check for VSS files
        vss_patterns = ["vss", "snapshot", "shadow"]
        for pattern in vss_patterns:
            if pattern.lower() in content.lower():
                findings.append(
                    {
                        "type": "vss_indicator",
                        "description": f"VSS-related entry: {pattern}",
                        "severity": "info",
                    }
                )

        return findings

    def _analyze_timeline(self, content: str) -> List[Dict]:
        """Analyze timeline for anomalies."""
        findings = []
        lines = content.split("\n")

        # Future dates
        future_pattern = r"(\d{4})-(\d{2})-(\d{2})"
        for line in lines:
            matches = re.findall(future_pattern, line)
            for match in matches:
                year = int(match[0])
                if year > datetime.now().year + 1:
                    findings.append(
                        {
                            "type": "future_date",
                            "description": f"Future timestamp: {match[0]}-{match[1]}-{match[2]}",
                            "severity": "high",
                        }
                    )

        # Zero timestamps
        if "00-00-0000" in content or "00-00-00" in content:
            findings.append(
                {
                    "type": "zero_timestamp",
                    "description": "Zero timestamps found",
                    "severity": "medium",
                }
            )

        # Count entries
        findings.append(
            {
                "type": "total_entries",
                "description": f"Timeline contains {len(lines)} entries",
                "severity": "info",
            }
        )

        return findings

    def _analyze_mft(self, content: str) -> List[Dict]:
        """Analyze MFT for indicators."""
        findings = []

        # Check for orphan files
        if "$OrphanFiles" in content:
            findings.append(
                {
                    "type": "orphan_files",
                    "description": "Orphaned files found (deleted but recoverable)",
                    "severity": "medium",
                }
            )

        # Count system files
        system_files = [
            "$MFT",
            "$MFTMirr",
            "$LogFile",
            "$Volume",
            "$AttrDef",
            "$Bitmap",
            "$Boot",
            "$BadClus",
            "$Secure",
            "$UpCase",
        ]

        found_systems = []
        for sf in system_files:
            if sf in content:
                found_systems.append(sf)

        findings.append(
            {
                "type": "system_files",
                "description": f"System files found: {', '.join(found_systems)}",
                "severity": "info",
            }
        )

        # Check for deleted entries
        deleted = content.count("-/")
        if deleted > 0:
            findings.append(
                {
                    "type": "deleted_entries",
                    "description": f"{deleted} deleted file entries in MFT",
                    "severity": "low",
                }
            )

        return findings

    def _analyze_logs(self, content: str) -> List[Dict]:
        """Analyze log files."""
        findings = []

        # Count event logs
        evtx_count = len(re.findall(r"\.evtx", content, re.IGNORECASE))
        findings.append(
            {
                "type": "event_logs",
                "description": f"{evtx_count} Windows event log files found",
                "severity": "info",
            }
        )

        # Check for log patterns
        if "No explicit" in content or "No log" in content:
            findings.append(
                {
                    "type": "few_logs",
                    "description": "Few or no log files found",
                    "severity": "medium",
                }
            )

        return findings

    def _analyze_ads(self, content: str) -> List[Dict]:
        """Analyze alternate data streams."""
        findings = []

        # Look for ADS patterns
        ads_pattern = r"([^:\s]+):([^:\s]+)"
        ads_matches = re.findall(ads_pattern, content)

        # Filter out known non-ADS
        real_ads = []
        for host, stream in ads_matches:
            if "$" not in host and len(stream) > 0:
                real_ads.append(f"{host}:{stream}")

        if real_ads:
            findings.append(
                {
                    "type": "ads_found",
                    "description": f"{len(real_ads)} potential alternate data streams",
                    "severity": "medium",
                }
            )

        # Check for Zone.Identifier (downloaded files)
        zone_count = content.count("Zone.Identifier")
        if zone_count > 0:
            findings.append(
                {
                    "type": "downloaded_files",
                    "description": f"{zone_count} downloaded files (Zone.Identifier streams)",
                    "severity": "low",
                }
            )

        return findings

    def _extract_evidence(self) -> Dict[str, Any]:
        """Extract structured evidence features for AI."""
        evidence = {
            "timestomping": {
                "future_dates": [],
                "zero_timestamps": [],
                "identical_timestamps": [],
                "total_checked": 0,
            },
            "shadow_copies": {
                "extend_exists": False,
                "system_volume_info": False,
                "indicators": [],
            },
            "alternate_data_streams": {
                "total_found": 0,
                "zone_identifier": 0,
                "samples": [],
            },
            "file_deletion": {"orphans": 0, "deleted_entries": 0, "recycle_bin": False},
            "registry": {"hives_found": [], "tool_indicators": []},
            "logs": {"event_logs": 0, "log_files": []},
        }

        logs_dir = self.output_dir / "logs"
        if logs_dir.exists():
            evtx_json_files = list(logs_dir.glob("**/*.evtx.json"))
            evtx_files = list(logs_dir.glob("**/*.evtx"))
            evidence["logs"]["event_logs"] = len(evtx_json_files) + len(evtx_files)
            evidence["logs"]["log_files"] = [f.name for f in evtx_json_files[:10]]

        # Process critical files first
        for file_info in self.file_classification["critical"]:
            self._process_critical_file(Path(file_info["path"]), evidence)

        # Process important files
        for file_info in self.file_classification["important"]:
            self._process_important_file(Path(file_info["path"]), evidence)

        return evidence

    def _process_critical_file(self, file_path: Path, evidence: Dict):
        """Process critical priority files."""
        try:
            with open(file_path, "r", errors="ignore") as f:
                content = f.read()

            if "usn_journal" in file_path.name:
                if "No USN journal" in content:
                    evidence["timestomping"]["future_dates"].append(
                        "USN journal missing"
                    )

            elif "registry" in file_path.name:
                hives = ["SAM", "SECURITY", "SOFTWARE", "SYSTEM", "NTUSER"]
                for hive in hives:
                    if hive in content:
                        evidence["registry"]["hives_found"].append(hive)

                tools = ["ccleaner", "bleachbit", "eraser"]
                for tool in tools:
                    if tool.lower() in content.lower():
                        evidence["registry"]["tool_indicators"].append(tool)

            elif "shadow" in file_path.name:
                if "$Extend" in content:
                    evidence["shadow_copies"]["extend_exists"] = True
                if "System Volume Information" in content:
                    evidence["shadow_copies"]["system_volume_info"] = True
                if "No shadow" in content:
                    evidence["shadow_copies"]["indicators"].append(
                        "No shadow copies found"
                    )

        except Exception as e:
            print(f"    [!] Error processing {file_path.name}: {e}")

    def _process_important_file(self, file_path: Path, evidence: Dict):
        """Process important priority files."""
        try:
            with open(file_path, "r", errors="ignore") as f:
                content = f.read()
                lines = content.split("\n")

            if "timeline" in file_path.name or "timestomp" in file_path.name:
                evidence["timestomping"]["total_checked"] = len(lines)

                # Find future dates
                for line in lines:
                    if match := re.search(r"(\d{4})-(\d{2})-(\d{2})", line):
                        year = int(match.group(1))
                        if year > datetime.now().year + 1:
                            evidence["timestomping"]["future_dates"].append(
                                f"{line[:80]}"
                            )

                if "00-00-0000" in content:
                    evidence["timestomping"]["zero_timestamps"].append(
                        "Found in timeline"
                    )

            elif "mft" in file_path.name:
                if "$OrphanFiles" in content:
                    evidence["file_deletion"]["orphans"] = content.count("$OrphanFiles")
                if "RECYCLER" in content or "Recycle.Bin" in content:
                    evidence["file_deletion"]["recycle_bin"] = True
                evidence["file_deletion"]["deleted_entries"] = content.count("-/")

            elif "hidden" in file_path.name:
                ads = re.findall(r"([^:\s]+):([^:\s]+)", content)
                evidence["alternate_data_streams"]["total_found"] = len(ads)
                evidence["alternate_data_streams"]["zone_identifier"] = content.count(
                    "Zone.Identifier"
                )
                evidence["alternate_data_streams"]["samples"] = [
                    f"{a[0]}:{a[1]}" for a in ads[:10]
                ]

            elif "logs" in file_path.name:
                pass

            elif file_path.suffix == ".json" and ".evtx." in file_path.name:
                pass

        except Exception as e:
            print(f"    [!] Error processing {file_path.name}: {e}")

    def _build_context(self) -> Dict[str, Any]:
        """Build AI-ready context from extracted evidence."""
        evidence = self._extract_evidence()

        context = {
            "system_prompt": self._get_system_prompt(),
            "evidence_summary": self._format_evidence_summary(evidence),
            "analysis_instructions": self._get_analysis_instructions(),
            "json_output_schema": self._get_output_schema(),
        }

        return context

    def _get_system_prompt(self) -> str:
        """Get system prompt for AI."""
        return """You are an expert forensic analyst specializing in digital forensics and anti-forensic technique detection. Your role is to analyze extracted disk image artifacts and identify evidence of anti-forensic activities.

KNOWLEDGE AREAS:
- Windows NTFS filesystem forensics
- Master File Table (MFT) analysis
- USN Journal interpretation
- Registry forensics (SAM, SECURITY, SOFTWARE, SYSTEM hives)
- Volume Shadow Copy (VSS) analysis
- Alternate Data Streams (ADS)
- Timestomping techniques
- Log manipulation and clearing
- Common anti-forensic tools (Timestomp, CCleaner, BleachBit, etc.)

RESPONSE REQUIREMENTS:
1. Provide reasoning for each finding
2. Distinguish between normal Windows behavior and suspicious activity
3. Correlate findings across multiple artifacts
4. Assign severity levels with justification
5. Suggest specific follow-up investigations"""

    def _format_evidence_summary(self, evidence: Dict) -> str:
        """Format evidence for AI context."""
        summary = f"""
EVIDENCE SUMMARY
================

TIMESTOMPING ANALYSIS:
- Files with future dates: {len(evidence["timestomping"]["future_dates"])}
- Zero timestamps: {len(evidence["timestomping"]["zero_timestamps"])}
- Total timeline entries analyzed: {evidence["timestomping"]["total_checked"]}
- Sample future dates: {evidence["timestomping"]["future_dates"][:5]}

SHADOW COPY STATUS:
- $Extend exists: {evidence["shadow_copies"]["extend_exists"]}
- System Volume Information: {evidence["shadow_copies"]["system_volume_info"]}
- Other indicators: {evidence["shadow_copies"]["indicators"]}

ALTERNATE DATA STREAMS:
- Total ADS found: {evidence["alternate_data_streams"]["total_found"]}
- Zone.Identifier (downloaded): {evidence["alternate_data_streams"]["zone_identifier"]}
- Samples: {evidence["alternate_data_streams"]["samples"][:5]}

FILE DELETION:
- Orphaned files: {evidence["file_deletion"]["orphans"]}
- Deleted MFT entries: {evidence["file_deletion"]["deleted_entries"]}
- Recycle Bin present: {evidence["file_deletion"]["recycle_bin"]}

REGISTRY:
- Hives found: {evidence["registry"]["hives_found"]}
- Tool indicators: {evidence["registry"]["tool_indicators"]}

LOG FILES:
- Event logs (.evtx): {evidence["logs"]["event_logs"]}
"""
        return summary

    def _get_analysis_instructions(self) -> str:
        """Get analysis instructions for AI."""
        return """
TASK:
Analyze the extracted forensic artifacts and produce a structured analysis report.

FOR EACH FINDING, PROVIDE:
1. Technique detected (e.g., timestomping, shadow copy deletion)
2. Severity (LOW/MEDIUM/HIGH/CRITICAL)
3. Evidence: Specific file entries or data that supports the finding
4. Explanation: WHY this indicates anti-forensic activity vs normal behavior
5. Recommendation: Specific follow-up investigation steps

CORRELATE ACROSS ARTIFACTS:
- Timestomping: Cross-reference timeline with USN journal timestamps
- Deletion: Check MFT deleted entries + Recycle Bin + orphan files
- Shadow Copies: Verify $Extend + System Volume Information status
- ADS: Note which files have streams and their types

FINAL OUTPUT:
Provide a JSON object with your findings (schema below).
"""

    def _get_output_schema(self) -> str:
        """Get JSON output schema."""
        return """
JSON Output Schema:
{
  "findings": [
    {
      "technique": "timestomping|shadow_deletion|ads|deletion|registry_tampering|log_clearing|other",
      "severity": "LOW|MEDIUM|HIGH|CRITICAL",
      "evidence": "Specific data supporting this finding",
      "explanation": "Detailed reasoning for why this is/isn't suspicious",
      "recommendation": "Specific follow-up investigation",
      "file_source": "Which artifact file contains this evidence"
    }
  ],
  "summary": "Overall assessment in 2-3 sentences",
  "risk_level": "LOW|MEDIUM|HIGH|CRITICAL",
  "recommendations": ["List of general recommendations"]
}
"""

    def _calculate_stats(self) -> Dict[str, Any]:
        """Calculate preprocessing statistics."""
        total_size = 0
        total_files = 0

        for category, files in self.file_classification.items():
            for f in files:
                total_size += f["size_bytes"]
                total_files += 1

        return {
            "total_files_processed": total_files,
            "total_size_bytes": total_size,
            "total_size_mb": round(total_size / (1024 * 1024), 2),
            "files_by_priority": {
                k: len(v) for k, v in self.file_classification.items()
            },
        }


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="Preprocess forensic artifacts for AI analysis"
    )
    parser.add_argument(
        "output_dir", help="Directory containing extracted forensic artifacts"
    )
    parser.add_argument("-o", "--output", help="Output file for preprocessed data")
    args = parser.parse_args()

    preprocessor = ForensicPreprocessor(args.output_dir)
    result = preprocessor.run_full_preprocessing()

    if args.output:
        with open(args.output, "w") as f:
            json.dump(result, f, indent=2, default=str)
        print(f"[+] Saved to: {args.output}")


if __name__ == "__main__":
    main()
