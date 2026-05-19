#!/usr/bin/env python3
"""
Forensic Artifact Extractor Utility
Extracts logs, MFT, USN journals, and registry hives from disk images
for anti-forensic technique detection.

Usage:
    python3 forensic_extractor.py <image> -o <output_dir> --all
    python3 forensic_extractor.py <image> --mft --registry --anti-forensic
    from forensic_extractor import ForensicExtractor
    extractor = ForensicExtractor("image.dd", "output")
    extractor.extract_everything()
"""

import os
import subprocess
import sys
import json
import argparse
from pathlib import Path
from typing import Optional, List, Dict, Tuple, Any


class ForensicExtractor:
    def __init__(self, image_path: str, output_dir: str):
        self.image_path = image_path
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.image_type = self._detect_image_type()
        self.partitions = self.get_partition_layout()

    def _detect_image_type(self) -> str:
        """Detect image type from file extension."""
        ext = Path(self.image_path).suffix.lower()
        if ext in [".e01", ".ewf"]:
            return "ewf"
        return "raw"

    def run_command(self, cmd: List[str], capture: bool = True) -> Tuple[int, str, str]:
        """Run a command and return exit code, stdout, stderr."""
        try:
            if capture:
                result = subprocess.run(
                    cmd, capture_output=True, text=True, timeout=300
                )
                return result.returncode, result.stdout, result.stderr
            else:
                result = subprocess.run(cmd, timeout=300)
                return result.returncode, "", ""
        except subprocess.TimeoutExpired:
            return -1, "", "Command timed out"
        except FileNotFoundError:
            return -1, "", f"Command not found: {cmd[0]}"
        except Exception as e:
            return -1, "", str(e)

    def get_partition_offset(self, partition_idx: int) -> int:
        """Get sector offset for a partition by index."""
        if partition_idx < len(self.partitions):
            part = self.partitions[partition_idx]
            start = part.get("start_int", 0)
            return start
        return 0

    def get_partition_offset_bytes(self, partition_idx: int) -> int:
        """Get byte offset for a partition by index."""
        return self.get_partition_offset(partition_idx) * 512

    def get_fls_cmd_base(self, sector_offset: int) -> List[str]:
        """Build base fls command with correct image type."""
        cmd = ["fls"]
        if self.image_type == "ewf":
            cmd.extend(["-i", "ewf"])
        cmd.extend(["-o", str(sector_offset)])
        return cmd

    def get_partition_layout(self) -> List[Dict]:
        """Get partition layout using mmls."""
        cmd = ["mmls"]
        if self.image_type == "ewf":
            cmd.extend(["-i", "ewf"])
        cmd.append(self.image_path)

        code, stdout, stderr = self.run_command(cmd)
        partitions = []

        if code == 0 and stdout:
            lines = stdout.strip().split("\n")
            for line in lines[3:]:
                parts = line.split()
                if len(parts) >= 4:
                    slot = parts[0]

                    if slot.startswith("000:") or "-------" in slot:
                        continue

                    is_partition = False
                    part_num = 0

                    if ":" in slot:
                        slot_parts = slot.split(":")
                        if len(slot_parts) == 2 and slot_parts[0].isdigit():
                            part_num = (
                                int(slot_parts[1]) if slot_parts[1].isdigit() else 0
                            )
                            is_partition = True
                    elif slot.replace("-", "").isdigit():
                        is_partition = True

                    if is_partition:
                        try:
                            start_sector = int(parts[2])
                            desc = (
                                " ".join(parts[5:])
                                if len(parts) > 5
                                else " ".join(parts[4:])
                                if len(parts) > 4
                                else ""
                            )
                            desc_lower = desc.lower()

                            skip_patterns = [
                                "unallocated",
                                "meta",
                                "header",
                                "table",
                                "gpt ",
                                "safety",
                            ]

                            if start_sector > 0 and not any(
                                p in desc_lower for p in skip_patterns
                            ):
                                partitions.append(
                                    {
                                        "slot": parts[0],
                                        "partition_num": part_num,
                                        "start": parts[2],
                                        "start_int": start_sector,
                                        "end": parts[3],
                                        "length": parts[4],
                                        "desc": desc,
                                    }
                                )
                        except (ValueError, IndexError):
                            pass
        return partitions

    def detect_filesystem(self, offset: int = 0) -> Optional[str]:
        """Detect filesystem type at given offset."""
        cmd = self.get_fls_cmd_base(offset)
        cmd.append(self.image_path)

        code, stdout, stderr = self.run_command(cmd)
        if code == 0 and stdout:
            return "auto"

        for fs in ["ntfs", "fat", "ext2", "ext3", "ext4", "hfs", "apfs"]:
            cmd = self.get_fls_cmd_base(offset)
            cmd.extend(["-f", fs])
            cmd.append(self.image_path)

            code, stdout, stderr = self.run_command(cmd)
            if code == 0:
                return fs
        return "ntfs"

    def extract_mft(self, partition_num: int = 0) -> bool:
        """Extract and parse MFT records from partition."""
        output_file = self.output_dir / f"mft_partition_{partition_num}.txt"
        offset = self.get_partition_offset(partition_num)
        fs_type = self.detect_filesystem(offset)

        cmd = self.get_fls_cmd_base(offset)
        if fs_type and fs_type != "auto":
            cmd.extend(["-f", fs_type])
        cmd.append(self.image_path)

        code, stdout, stderr = self.run_command(cmd)

        if code == 0 and stdout:
            with open(output_file, "w") as f:
                f.write(f"MFT Listing for Partition {partition_num}\n")
                f.write(f"Image: {self.image_path}\n")
                f.write(f"Offset: {offset} bytes\n")
                f.write(f"Filesystem: {fs_type}\n")
                f.write("=" * 80 + "\n\n")
                f.write(stdout)
            return True
        elif stderr:
            with open(output_file, "w") as f:
                f.write(f"MFT Listing for Partition {partition_num}\n")
                f.write(f"Error: {stderr}\n")
        return False

    def extract_usn_journal(self, partition_num: int = 0) -> bool:
        """Extract USN journal from NTFS partition."""
        output_file = self.output_dir / f"usn_journal_partition_{partition_num}.txt"
        offset = self.get_partition_offset(partition_num)
        fs_type = self.detect_filesystem(offset)

        cmd = self.get_fls_cmd_base(offset)
        cmd.append("-r")
        if fs_type and fs_type != "auto":
            cmd.extend(["-f", fs_type])
        cmd.append(self.image_path)

        code, stdout, stderr = self.run_command(cmd)

        usn_files = []
        if code == 0 and stdout:
            for line in stdout.split("\n"):
                if "$UsnJrnl" in line or "usn" in line.lower():
                    usn_files.append(line)

        with open(output_file, "w") as f:
            f.write(f"USN Journal Files for Partition {partition_num}\n")
            f.write(f"Image: {self.image_path}\n")
            f.write(f"Offset: {offset} bytes\n")
            f.write(f"Filesystem: {fs_type}\n")
            f.write("=" * 80 + "\n\n")
            if usn_files:
                f.write("USN Journal Entries Found:\n")
                f.write("\n".join(usn_files))
            else:
                f.write("No USN journal files found.\n")
                f.write("\nFull file list for reference:\n")
                f.write(stdout[:50000])
        return True

    def extract_registry_hives(self, partition_num: int = 0) -> bool:
        """Extract Windows registry hives from NTFS partition."""
        output_file = self.output_dir / f"registry_partition_{partition_num}.txt"
        offset = self.get_partition_offset(partition_num)
        fs_type = self.detect_filesystem(offset)

        cmd = ["fls", "-o", str(offset), "-r"]
        if fs_type and fs_type != "auto":
            cmd.extend(["-f", fs_type])
        cmd.append(self.image_path)

        code, stdout, stderr = self.run_command(cmd)

        registry_patterns = [
            "System32/config/SAM",
            "System32/config/SECURITY",
            "System32/config/SOFTWARE",
            "System32/config/SYSTEM",
            "System32/config/DEFAULT",
            "NTUSER.DAT",
            "USRCLASS.DAT",
        ]

        registry_hives = []
        if code == 0 and stdout:
            for line in stdout.split("\n"):
                line_lower = line.lower()
                for pattern in registry_patterns:
                    if pattern.lower() in line_lower:
                        registry_hives.append(line)
                        break

        with open(output_file, "w") as f:
            f.write(f"Registry Hives for Partition {partition_num}\n")
            f.write(f"Image: {self.image_path}\n")
            f.write(f"Offset: {offset} bytes\n")
            f.write(f"Filesystem: {fs_type}\n")
            f.write("=" * 80 + "\n\n")
            if registry_hives:
                f.write("Registry Hives Found:\n")
                f.write("\n".join(registry_hives))
            else:
                f.write("No registry hives found in standard locations.\n")
                if code == 0 and stdout:
                    f.write("\nSearching full output for .DAT/.LOG files...\n")
                    for line in stdout.split("\n"):
                        if ".DAT" in line or ".LOG" in line:
                            f.write(line + "\n")
        return True

    def extract_logs(self, partition_num: int = 0) -> bool:
        """Extract Windows event logs and other log files."""
        output_file = self.output_dir / f"logs_partition_{partition_num}.txt"
        offset = self.get_partition_offset(partition_num)
        fs_type = self.detect_filesystem(offset)

        cmd = ["fls", "-o", str(offset), "-r"]
        if fs_type and fs_type != "auto":
            cmd.extend(["-f", fs_type])
        cmd.append(self.image_path)

        code, stdout, stderr = self.run_command(cmd)

        log_patterns = [".evtx", ".log", "/Logs", "/Temp", "/Debug", "/Tracing"]

        log_files = []
        if code == 0 and stdout:
            for line in stdout.split("\n"):
                for pattern in log_patterns:
                    if pattern.lower() in line.lower():
                        log_files.append(line)
                        break

        with open(output_file, "w") as f:
            f.write(f"Log Files for Partition {partition_num}\n")
            f.write(f"Image: {self.image_path}\n")
            f.write(f"Offset: {offset} bytes\n")
            f.write(f"Filesystem: {fs_type}\n")
            f.write("=" * 80 + "\n\n")
            if log_files:
                f.write("Log Files Found:\n")
                f.write("\n".join(log_files))
            else:
                f.write("No explicit log files found.\n")
        return True

    def extract_timeline(self, partition_num: int = 0) -> bool:
        """Extract complete timeline for anti-forensic analysis."""
        output_file = self.output_dir / f"timeline_partition_{partition_num}.txt"
        offset = self.get_partition_offset(partition_num)
        fs_type = self.detect_filesystem(offset)

        cmd = ["fls", "-o", str(offset), "-r", "-l"]
        if fs_type and fs_type != "auto":
            cmd.extend(["-f", fs_type])
        cmd.append(self.image_path)

        code, stdout, stderr = self.run_command(cmd)

        with open(output_file, "w") as f:
            f.write(f"Full Timeline for Partition {partition_num}\n")
            f.write(f"Image: {self.image_path}\n")
            f.write(f"Offset: {offset} bytes\n")
            f.write(f"Filesystem: {fs_type}\n")
            f.write("=" * 80 + "\n\n")
            if code == 0 and stdout:
                f.write(stdout)
            else:
                f.write(f"Error: {stderr}\n")
        return True

    def detect_shadow_copies(self, partition_num: int = 0) -> bool:
        """Detect shadow copies (anti-forensic technique)."""
        output_file = self.output_dir / f"shadow_copies_partition_{partition_num}.txt"
        offset = self.get_partition_offset(partition_num)
        fs_type = self.detect_filesystem(offset)

        cmd = ["fls", "-o", str(offset), "-r"]
        if fs_type and fs_type != "auto":
            cmd.extend(["-f", fs_type])
        cmd.append(self.image_path)

        code, stdout, stderr = self.run_command(cmd)

        shadow_indicators = []
        keywords = [
            "shadow",
            "vss",
            "snapshot",
            "$Extend",
            "$Volume",
            "System Volume Information",
        ]

        if code == 0 and stdout:
            for line in stdout.split("\n"):
                for kw in keywords:
                    if kw.lower() in line.lower():
                        shadow_indicators.append(line)
                        break

        with open(output_file, "w") as f:
            f.write(f"Shadow Copy / VSS Indicators for Partition {partition_num}\n")
            f.write(f"Image: {self.image_path}\n")
            f.write(f"Offset: {offset} bytes\n")
            f.write(f"Filesystem: {fs_type}\n")
            f.write("=" * 80 + "\n\n")
            if shadow_indicators:
                f.write("Potential Shadow Copy / VSS Related Files:\n")
                f.write("\n".join(shadow_indicators))
            else:
                f.write("No shadow copy indicators found.\n")
        return True

    def detect_hidden_structures(self, partition_num: int = 0) -> bool:
        """Detect hidden files and alternate data streams."""
        output_file = (
            self.output_dir / f"hidden_structures_partition_{partition_num}.txt"
        )
        offset = self.get_partition_offset(partition_num)
        fs_type = self.detect_filesystem(offset)

        cmd = ["fls", "-o", str(offset), "-r", "-p"]
        if fs_type and fs_type != "auto":
            cmd.extend(["-f", fs_type])
        cmd.append(self.image_path)

        code, stdout, stderr = self.run_command(cmd)

        hidden_items = []
        if code == 0 and stdout:
            for line in stdout.split("\n"):
                if ":" in line:
                    parts = line.split(":")
                    if len(parts) > 2:
                        hidden_items.append(line)

        with open(output_file, "w") as f:
            f.write(f"Hidden Structures / ADS for Partition {partition_num}\n")
            f.write(f"Image: {self.image_path}\n")
            f.write(f"Offset: {offset} bytes\n")
            f.write(f"Filesystem: {fs_type}\n")
            f.write("=" * 80 + "\n\n")
            if hidden_items:
                f.write("Potential Alternate Data Streams / Hidden Data:\n")
                f.write("\n".join(hidden_items))
            else:
                f.write("No hidden structures/ADS found.\n")
        return True

    def extract_timeline(self, partition_num: int = 0) -> bool:
        """Extract complete timeline for anti-forensic analysis."""
        output_file = self.output_dir / f"timeline_partition_{partition_num}.txt"
        offset = self.get_partition_offset(partition_num)

        cmd = ["fls", "-o", str(offset), "-r", "-l", self.image_path]
        code, stdout, stderr = self.run_command(cmd)

        with open(output_file, "w") as f:
            f.write(f"Full Timeline for Partition {partition_num}\n")
            f.write(f"Image: {self.image_path}\n")
            f.write(f"Offset: {offset} bytes\n")
            f.write("=" * 80 + "\n\n")
            if code == 0 and stdout:
                f.write(stdout)
            else:
                f.write(f"Error: {stderr}\n")
        return True

    def detect_shadow_copies(self, partition_num: int = 0) -> bool:
        """Detect shadow copies (anti-forensic technique)."""
        output_file = self.output_dir / f"shadow_copies_partition_{partition_num}.txt"
        offset = self.get_partition_offset(partition_num)

        cmd = ["fls", "-o", str(offset), "-r", self.image_path]
        code, stdout, stderr = self.run_command(cmd)

        shadow_indicators = []
        keywords = [
            "shadow",
            "vss",
            "snapshot",
            "$Extend",
            "$Volume",
            "System Volume Information",
        ]

        if code == 0 and stdout:
            for line in stdout.split("\n"):
                for kw in keywords:
                    if kw.lower() in line.lower():
                        shadow_indicators.append(line)
                        break

        with open(output_file, "w") as f:
            f.write(f"Shadow Copy / VSS Indicators for Partition {partition_num}\n")
            f.write(f"Image: {self.image_path}\n")
            f.write("=" * 80 + "\n\n")
            if shadow_indicators:
                f.write("Potential Shadow Copy / VSS Related Files:\n")
                f.write("\n".join(shadow_indicators))
            else:
                f.write("No shadow copy indicators found.\n")
        return True

    def detect_hidden_structures(self, partition_num: int = 0) -> bool:
        """Detect hidden files and alternate data streams."""
        output_file = (
            self.output_dir / f"hidden_structures_partition_{partition_num}.txt"
        )
        offset = self.get_partition_offset(partition_num)

        cmd = ["fls", "-o", str(offset), "-r", "-p", self.image_path]
        code, stdout, stderr = self.run_command(cmd)

        hidden_items = []
        if code == 0 and stdout:
            for line in stdout.split("\n"):
                if ":" in line:
                    parts = line.split(":")
                    if len(parts) > 2:
                        hidden_items.append(line)

        with open(output_file, "w") as f:
            f.write(f"Hidden Structures / ADS for Partition {partition_num}\n")
            f.write(f"Image: {self.image_path}\n")
            f.write("=" * 80 + "\n\n")
            if hidden_items:
                f.write("Potential Alternate Data Streams / Hidden Data:\n")
                f.write("\n".join(hidden_items))
            else:
                f.write("No hidden structures/ADS found.\n")
        return True

    def detect_timestomping(self, partition_num: int = 0) -> bool:
        """Detect timestamp manipulation (anti-forensic)."""
        output_file = (
            self.output_dir / f"timestomp_indicators_partition_{partition_num}.txt"
        )
        offset = self.get_partition_offset(partition_num)

        cmd = ["fls", "-o", str(offset), "-r", "-l", self.image_path]
        code, stdout, stderr = self.run_command(cmd)

        with open(output_file, "w") as f:
            f.write(f"Timestamp Analysis for Partition {partition_num}\n")
            f.write(f"Image: {self.image_path}\n")
            f.write("=" * 80 + "\n\n")
            if code == 0 and stdout:
                f.write("Full file listing with timestamps:\n")
                f.write("Format: mode uid gid size date time name\n\n")
                f.write(stdout)
            else:
                f.write(f"Error: {stderr}\n")
        return True

    def extract_all_artifacts(self, partition_num: int = 0) -> Dict[str, bool]:
        """Extract all artifact types for a specific partition."""
        results = {}
        results["mft"] = self.extract_mft(partition_num)
        results["usn"] = self.extract_usn_journal(partition_num)
        results["registry"] = self.extract_registry_hives(partition_num)
        results["logs"] = self.extract_logs(partition_num)
        results["timeline"] = self.extract_timeline(partition_num)
        results["shadow_copies"] = self.detect_shadow_copies(partition_num)
        results["hidden_structures"] = self.detect_hidden_structures(partition_num)
        results["timestomp"] = self.detect_timestomping(partition_num)
        return results

    def extract_everything(self) -> Dict[str, Any]:
        """Extract all artifacts from all partitions and return summary."""
        summary = {
            "image": self.image_path,
            "partitions": [],
            "extracted_files": {
                "mft": [],
                "usn_journals": [],
                "registry": [],
                "logs": [],
                "timelines": [],
                "shadow_copies": [],
                "hidden_structures": [],
                "timestomp": [],
            },
            "status": {},
        }

        for part in self.partitions:
            summary["partitions"].append(
                {"slot": part["slot"], "start": part["start"], "desc": part["desc"]}
            )

        for i in range(len(self.partitions)):
            results = self.extract_all_artifacts(i)
            summary["status"][f"partition_{i}"] = results

            summary["extracted_files"]["mft"].append(f"mft_partition_{i}.txt")
            summary["extracted_files"]["usn_journals"].append(
                f"usn_journal_partition_{i}.txt"
            )
            summary["extracted_files"]["registry"].append(f"registry_partition_{i}.txt")
            summary["extracted_files"]["logs"].append(f"logs_partition_{i}.txt")
            summary["extracted_files"]["timelines"].append(
                f"timeline_partition_{i}.txt"
            )
            summary["extracted_files"]["shadow_copies"].append(
                f"shadow_copies_partition_{i}.txt"
            )
            summary["extracted_files"]["hidden_structures"].append(
                f"hidden_structures_partition_{i}.txt"
            )
            summary["extracted_files"]["timestomp"].append(
                f"timestomp_indicators_partition_{i}.txt"
            )

        summary_file = self.output_dir / "extraction_summary.json"
        with open(summary_file, "w") as f:
            json.dump(summary, f, indent=2)

        return summary


def main():
    parser = argparse.ArgumentParser(
        description="Forensic Artifact Extractor - Extract logs, MFT, USN journals, and registry hives",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s image.dd -o output --all
  %(prog)s image.E01 -o output --mft --registry
  %(prog)s image.dd --anti-forensic
  
Library usage:
  from forensic_extractor import ForensicExtractor
  extractor = ForensicExtractor("image.dd", "output")
  result = extractor.extract_everything()
        """,
    )
    parser.add_argument("image", help="Path to disk image file")
    parser.add_argument(
        "-o",
        "--output",
        default="forensic_output",
        help="Output directory (default: forensic_output)",
    )
    parser.add_argument(
        "-p",
        "--partition",
        type=int,
        default=-1,
        help="Specific partition number (default: all)",
    )
    parser.add_argument("--mft", action="store_true", help="Extract MFT only")
    parser.add_argument("--usn", action="store_true", help="Extract USN journals only")
    parser.add_argument(
        "--registry", action="store_true", help="Extract registry hives only"
    )
    parser.add_argument("--logs", action="store_true", help="Extract logs only")
    parser.add_argument("--timeline", action="store_true", help="Extract timeline only")
    parser.add_argument(
        "--anti-forensic", action="store_true", help="Run anti-forensic detection only"
    )
    parser.add_argument("--all", action="store_true", help="Extract everything")

    args = parser.parse_args()

    if not os.path.exists(args.image):
        print(f"Error: Image file not found: {args.image}")
        sys.exit(1)

    extractor = ForensicExtractor(args.image, args.output)

    print(f"Processing image: {args.image}")
    print(f"Output directory: {args.output}")
    print(f"Found {len(extractor.partitions)} partitions")

    if args.all:
        print("Extracting all artifacts...")
        summary = extractor.extract_everything()
        print(
            f"Extraction complete. Summary: {len(summary['extracted_files']['mft'])} MFT, "
            f"{len(summary['extracted_files']['registry'])} registry files"
        )
        print(f"Summary saved to {args.output}/extraction_summary.json")

    elif args.anti_forensic:
        print("Running anti-forensic detection...")
        for i in range(len(extractor.partitions)):
            extractor.detect_shadow_copies(i)
            extractor.detect_hidden_structures(i)
            extractor.detect_timestomping(i)
        print("Anti-forensic detection complete.")

    else:
        target_partitions = (
            [args.partition]
            if args.partition >= 0
            else range(len(extractor.partitions))
        )

        if args.mft:
            for i in target_partitions:
                extractor.extract_mft(i)
        if args.usn:
            for i in target_partitions:
                extractor.extract_usn_journal(i)
        if args.registry:
            for i in target_partitions:
                extractor.extract_registry_hives(i)
        if args.logs:
            for i in target_partitions:
                extractor.extract_logs(i)
        if args.timeline:
            for i in target_partitions:
                extractor.extract_timeline(i)

        if not any([args.mft, args.usn, args.registry, args.logs, args.timeline]):
            print("No extraction option specified. Use --all for full extraction.")
            print("Use -h for help.")


if __name__ == "__main__":
    main()
