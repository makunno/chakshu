#!/usr/bin/env python3
"""
Anti-Forensic Analysis Script
Analyzes extracted forensic artifacts to detect anti-forensic techniques.

Usage:
    python3 analyze_antiforensic.py <output_directory>
    python3 analyze_antiforensic.py /path/to/forensic_output

    # Or use as library
    from analyze_antiforensic import AntiForensicAnalyzer
    analyzer = AntiForensicAnalyzer("output_dir")
    results = analyzer.analyze()
"""

import os
import re
import json
import argparse
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any, Optional
from collections import defaultdict


class AntiForensicAnalyzer:
    def __init__(self, output_dir: str):
        self.output_dir = Path(output_dir)
        self.results = {
            "analysis_time": datetime.now().isoformat(),
            "timestomping": [],
            "shadow_copy_deletion": [],
            "hidden_streams": [],
            "log_clearing": [],
            "registry_tampering": [],
            "file_deletion": [],
            "mft_anomalies": [],
            "summary": {},
        }

    def analyze(self) -> Dict[str, Any]:
        """Run all analysis modules and return results."""
        if not self.output_dir.exists():
            print(f"Error: Output directory not found: {self.output_dir}")
            return self.results

        print(f"[*] Analyzing: {self.output_dir}")

        self._analyze_timestomping()
        self._analyze_shadow_copies()
        self._analyze_hidden_streams()
        self._analyze_log_clearing()
        self._analyze_registry_tampering()
        self._analyze_file_deletion()
        self._analyze_mft_anomalies()
        self._generate_summary()

        return self.results

    def save_results(self, output_file: str = None):
        """Save analysis results to JSON file."""
        if output_file is None:
            output_file = self.output_dir / "antiforensic_analysis.json"
        else:
            output_file = Path(output_file)

        with open(output_file, "w") as f:
            json.dump(self.results, f, indent=2)

        print(f"\n[+] Results saved to: {output_file}")

    def print_report(self):
        """Print formatted analysis report."""
        print("\n" + "=" * 70)
        print("           ANTI-FORENSIC ANALYSIS REPORT")
        print("=" * 70)

        categories = [
            ("TIMESTOMPING DETECTION", self.results["timestomping"], "warning"),
            ("SHADOW COPY DELETION", self.results["shadow_copy_deletion"], "warning"),
            ("HIDDEN DATA STREAMS (ADS)", self.results["hidden_streams"], "info"),
            ("LOG CLEARING EVIDENCE", self.results["log_clearing"], "warning"),
            ("REGISTRY TAMPERING", self.results["registry_tampering"], "warning"),
            ("FILE DELETION TRACKING", self.results["file_deletion"], "info"),
            ("MFT ANOMALIES", self.results["mft_anomalies"], "warning"),
        ]

        total_findings = 0

        for title, findings, _ in categories:
            color = "  "
            if findings:
                color = " [!] "
                total_findings += len(findings)
            else:
                color = " [+] "

            print(f"\n{color}{title}")
            print("-" * 70)

            if findings:
                for f in findings[:10]:  # Limit output
                    print(f"    • {f}")
                if len(findings) > 10:
                    print(f"    ... and {len(findings) - 10} more")
            else:
                print("    No indicators found")

        print("\n" + "=" * 70)
        print(f"  SUMMARY: {total_findings} potential indicators detected")
        print("=" * 70)

        # Risk assessment
        if total_findings == 0:
            print("\n  ✅ LOW RISK: No obvious anti-forensic techniques detected")
        elif total_findings < 5:
            print("\n  ⚠️  MEDIUM RISK: Some anti-forensic indicators found")
        else:
            print("\n  🚨 HIGH RISK: Multiple anti-forensic techniques detected")

        print()

    def _analyze_timestomping(self):
        """Detect timestomping - modifying file timestamps."""
        timeline_files = list(self.output_dir.glob("timeline_partition_*.txt"))

        for tf in timeline_files:
            partition = tf.stem.split("_")[-1]

            try:
                with open(tf, "r", errors="ignore") as f:
                    content = f.read()
                    lines = content.split("\n")

                for line in lines:
                    # Skip header lines
                    if (
                        line.startswith("=")
                        or line.startswith("Timeline")
                        or not line.strip()
                    ):
                        continue

                    # Look for future dates (beyond current year + 1)
                    future_matches = re.findall(r"(\d{4})-(\d{2})-(\d{2})", line)
                    for match in future_matches:
                        year, month, day = int(match[0]), int(match[1]), int(match[2])
                        if year > datetime.now().year + 1:
                            self.results["timestomping"].append(
                                f"Partition {partition}: Future date {match[0]}-{match[1]}-{match[2]} in {line.split()[-1] if line.split() else 'unknown'}"
                            )

                    # Look for all-zero timestamps (00-00-0000)
                    if "00-00-0000" in line or "00-00-00" in line:
                        self.results["timestomping"].append(
                            f"Partition {partition}: Zero timestamp detected: {line[:80]}"
                        )

                    # Look for identical timestamps (common in timestomping tools)
                    parts = line.split()
                    if len(parts) >= 6:
                        try:
                            # Extract timestamps (format: YYYY-MM-DD HH:MM:SS)
                            timestamps = []
                            for p in parts:
                                if re.match(r"\d{4}-\d{2}-\d{2}", p):
                                    timestamps.append(p)
                                elif re.match(r"\d{2}:\d{2}:\d{2}", p):
                                    timestamps.append(p)

                            # If we have exactly 2 identical timestamps (SI=FN matching)
                            if len(timestamps) >= 4:
                                if (
                                    timestamps[0] == timestamps[2]
                                    and timestamps[1] == timestamps[3]
                                ):
                                    self.results["timestomping"].append(
                                        f"Partition {partition}: Identical SI/FN timestamps (possible timestomp): {line[:80]}"
                                    )
                        except:
                            pass

            except Exception as e:
                print(f"    [!] Error analyzing {tf}: {e}")

        # Check USN journal for timestomping evidence
        usn_files = list(self.output_dir.glob("usn_journal_partition_*.txt"))
        for usn in usn_files:
            partition = usn.stem.split("_")[-1]
            try:
                with open(usn, "r", errors="ignore") as f:
                    content = f.read()
                    if "No USN journal" in content or not content.strip():
                        self.results["timestomping"].append(
                            f"Partition {partition}: USN journal missing or empty - possible clearing"
                        )
            except:
                pass

    def _analyze_shadow_copies(self):
        """Detect shadow copy deletion (common anti-forensic technique)."""
        shadow_files = list(self.output_dir.glob("shadow_copies_partition_*.txt"))

        for sf in shadow_files:
            partition = sf.stem.split("_")[-1]

            try:
                with open(sf, "r", errors="ignore") as f:
                    content = f.read()

                # Check for evidence of shadow copy deletion
                if "No shadow copy" in content:
                    self.results["shadow_copy_deletion"].append(
                        f"Partition {partition}: No shadow copy indicators found"
                    )

                # Look for $Extend but missing System Volume Information
                if "$Extend" in content and "System Volume Information" not in content:
                    self.results["shadow_copy_deletion"].append(
                        f"Partition {partition}: $Extend exists but System Volume Information missing (possible deletion)"
                    )

                # Check timeline for vssadmin commands
                timeline_files = list(
                    self.output_dir.glob(f"timeline_partition_{partition}.txt")
                )
                if timeline_files:
                    with open(timeline_files[0], "r", errors="ignore") as f:
                        timeline = f.read()
                        if (
                            "vssadmin" in timeline.lower()
                            or "shadow copy" in timeline.lower()
                        ):
                            self.results["shadow_copy_deletion"].append(
                                f"Partition {partition}: Shadow copy related commands/files found"
                            )

            except Exception as e:
                print(f"    [!] Error analyzing {sf}: {e}")

    def _analyze_hidden_streams(self):
        """Detect Alternate Data Streams (ADS) - common hiding technique."""
        ads_files = list(self.output_dir.glob("hidden_structures_partition_*.txt"))

        for af in ads_files:
            partition = af.stem.split("_")[-1]

            try:
                with open(af, "r", errors="ignore") as f:
                    content = f.read()

                # Look for ADS (format: filename:streamname)
                ads_matches = re.findall(r"[^:\s]+:[^:\s]+", content)

                if ads_matches:
                    for match in ads_matches[:20]:
                        if "$" not in match and len(match.split(":")) == 2:
                            self.results["hidden_streams"].append(
                                f"Partition {partition}: ADS detected: {match}"
                            )

                # Count potential ADS
                if (
                    "Alternate Data Streams" in content
                    and "found" not in content.lower()
                ):
                    self.results["hidden_streams"].append(
                        f"Partition {partition}: Potential hidden data streams detected"
                    )

            except Exception as e:
                print(f"    [!] Error analyzing {af}: {e}")

    def _analyze_log_clearing(self):
        """Detect evidence of log clearing."""
        log_files = list(self.output_dir.glob("logs_partition_*.txt"))

        for lf in log_files:
            partition = lf.stem.split("_")[-1]

            try:
                with open(lf, "r", errors="ignore") as f:
                    content = f.read()

                # Look for .evtx files (Windows Event Logs)
                evtx_count = len(re.findall(r"\.evtx", content, re.IGNORECASE))
                if evtx_count == 0:
                    self.results["log_clearing"].append(
                        f"Partition {partition}: No Windows event log files (.evtx) found in listing"
                    )

                # Check timeline for log-related deletion commands
                timeline_files = list(
                    self.output_dir.glob(f"timeline_partition_{partition}.txt")
                )
                if timeline_files:
                    with open(timeline_files[0], "r", errors="ignore") as f:
                        timeline = f.read()
                        suspicious = ["wevtutil", "clear-log", "eventlog", ".log"]
                        for term in suspicious:
                            if term.lower() in timeline.lower():
                                self.results["log_clearing"].append(
                                    f"Partition {partition}: Log-related file/command found: {term}"
                                )

            except Exception as e:
                print(f"    [!] Error analyzing {lf}: {e}")

        logs_dir = self.output_dir / "logs"
        if logs_dir.exists():
            evtx_json_files = list(logs_dir.glob("**/*.evtx.json"))
            evtx_files = list(logs_dir.glob("**/*.evtx"))
            total_evtx = len(evtx_json_files) + len(evtx_files)

            if total_evtx > 0:
                self.results["log_clearing"].append(
                    f"Found {total_evtx} Windows Event Log files (.evtx) extracted"
                )
            else:
                self.results["log_clearing"].append(
                    "No Windows Event Logs (.evtx) found in extracted logs directory"
                )

    def _analyze_registry_tampering(self):
        """Detect registry tampering - account deletion, tool installation."""
        reg_files = list(self.output_dir.glob("registry_partition_*.txt"))

        suspicious_patterns = {
            "forensic_tools": [
                "ccleaner",
                "bleachbit",
                "evidence",
                "eliminator",
                "wiper",
                "eraser",
                "privacy",
            ],
            "account_deletion": ["sam", "security"],
            "service_deletion": ["services", "system"],
            "run_keys": ["run\\", "runonce"],
        }

        for rf in reg_files:
            partition = rf.stem.split("_")[-1]

            try:
                with open(rf, "r", errors="ignore") as f:
                    content = f.read()

                # Check for suspicious registry patterns
                for category, patterns in suspicious_patterns.items():
                    for pattern in patterns:
                        if pattern.lower() in content.lower():
                            if category == "forensic_tools":
                                self.results["registry_tampering"].append(
                                    f"Partition {partition}: Potential forensic tool indicator: {pattern}"
                                )
                            elif category == "account_deletion":
                                if content.count("sam") < 2:  # Few SAM references
                                    self.results["registry_tampering"].append(
                                        f"Partition {partition}: Unusual SAM/SECURITY hive activity"
                                    )

            except Exception as e:
                print(f"    [!] Error analyzing {rf}: {e}")

    def _analyze_file_deletion(self):
        """Detect evidence of file deletion."""
        mft_files = list(self.output_dir.glob("mft_partition_*.txt"))

        for mf in mft_files:
            partition = mf.stem.split("_")[-1]

            try:
                with open(mf, "r", errors="ignore") as f:
                    content = f.read()

                # Look for $OrphanFiles (deleted files with recoverable data)
                if "$OrphanFiles" in content:
                    orphan_count = content.count("$OrphanFiles")
                    self.results["file_deletion"].append(
                        f"Partition {partition}: Orphaned files found (deleted but recoverable): {orphan_count} entries"
                    )

                # Check for deleted entries (prefixed with *)
                deleted_count = content.count("-/")
                if deleted_count > 0:
                    self.results["file_deletion"].append(
                        f"Partition {partition}: Deleted files in MFT: {deleted_count} entries"
                    )

                # Check for Recycle Bin
                if "RECYCLER" in content or "Recycle.Bin" in content:
                    self.results["file_deletion"].append(
                        f"Partition {partition}: Recycle Bin found - check for deleted files"
                    )

            except Exception as e:
                print(f"    [!] Error analyzing {mf}: {e}")

    def _analyze_mft_anomalies(self):
        """Detect MFT anomalies and suspicious entries."""
        mft_files = list(self.output_dir.glob("mft_partition_*.txt"))

        suspicious_paths = [
            "temp",
            "tmp",
            "appdata",
            "local\\temp",
            "downloads",
            "recent",
            "prefetch",
        ]

        for mf in mft_files:
            partition = mf.stem.split("_")[-1]

            try:
                with open(mf, "r", errors="ignore") as f:
                    lines = f.readlines()

                # Check for suspicious MFT entries
                entry_count = 0
                system_file_count = 0

                for line in lines:
                    if "$" in line:  # System files
                        system_file_count += 1

                    # Look for suspicious paths
                    for spath in suspicious_paths:
                        if spath.lower() in line.lower():
                            self.results["mft_anomalies"].append(
                                f"Partition {partition}: Suspicious path: {line.strip()[:70]}"
                            )

                # Report MFT size
                if system_file_count > 0:
                    self.results["mft_anomalies"].append(
                        f"Partition {partition}: MFT contains {system_file_count} system file entries"
                    )

            except Exception as e:
                print(f"    [!] Error analyzing {mf}: {e}")

    def _generate_summary(self):
        """Generate summary statistics."""
        self.results["summary"] = {
            "total_timestomping_indicators": len(self.results["timestomping"]),
            "total_shadow_copy_indicators": len(self.results["shadow_copy_deletion"]),
            "total_ads_indicators": len(self.results["hidden_streams"]),
            "total_log_clearing_indicators": len(self.results["log_clearing"]),
            "total_registry_indicators": len(self.results["registry_tampering"]),
            "total_deletion_indicators": len(self.results["file_deletion"]),
            "total_mft_anomalies": len(self.results["mft_anomalies"]),
        }

        total = sum(self.results["summary"].values())
        self.results["summary"]["total_indicators"] = total

        if total == 0:
            self.results["summary"]["risk_level"] = "LOW"
        elif total < 5:
            self.results["summary"]["risk_level"] = "MEDIUM"
        else:
            self.results["summary"]["risk_level"] = "HIGH"


def main():
    parser = argparse.ArgumentParser(
        description="Anti-Forensic Analysis Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s /path/to/forensic_output
  %(prog)s ./output -o analysis_results.json
  %(prog)s ./output --verbose
        """,
    )
    parser.add_argument(
        "output_dir", help="Directory containing extracted forensic artifacts"
    )
    parser.add_argument("-o", "--output", help="Output file for JSON results")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")

    args = parser.parse_args()

    analyzer = AntiForensicAnalyzer(args.output_dir)
    results = analyzer.analyze()

    if args.output:
        analyzer.save_results(args.output)

    analyzer.print_report()


if __name__ == "__main__":
    main()
