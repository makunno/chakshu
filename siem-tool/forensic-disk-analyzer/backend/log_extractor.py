#!/usr/bin/env python3
"""
Log File Extractor for Disk Images
Extracts actual log file contents from disk images, converts binary formats
(.evtx) to text/JSON, and organizes for log parsing.

Usage:
    python3 log_extractor.py <image> -o <output_dir>
    from log_extractor import LogExtractor
    extractor = LogExtractor("image.E01", "output")
    report = extractor.extract_all(progress_callback=my_callback)
"""

import os
import subprocess
import sys
import json
import argparse
from pathlib import Path
from typing import Optional, List, Dict, Tuple, Any
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
import re


@dataclass
class LogEntry:
    inode: str
    path: str
    size: int
    file_type: str
    partition: int
    is_allocated: bool = True


@dataclass
class ExtractionReport:
    image: str
    extraction_time: str
    total_logs_found: int = 0
    total_logs_extracted: int = 0
    total_size_mb: float = 0.0
    by_type: Dict[str, int] = field(default_factory=dict)
    errors: List[Dict[str, str]] = field(default_factory=list)
    extracted_files: List[str] = field(default_factory=list)


class LogExtractor:
    WINDOWS_LOG_PATHS = [
        "windows/system32/winevt/logs",
        "windows/system32/winevt",
        "windows/logs",
        "windows/inf",
        "windows/debug",
        "windows/temp",
        "programdata/microsoft/windows/wer",
        "programdata/microsoft/windows/wdi",
    ]

    LINUX_LOG_PATHS = [
        "var/log/",
    ]

    SPECIFIC_LOG_FILES = [
        "setupact.log",
        "setuperr.log",
        "dism.log",
        "cbs.log",
        "windowsupdate.log",
        "setupapi.dev.log",
        "auth.log",
        "syslog",
        "kern.log",
        "messages",
        "secure",
        "daemon.log",
        "cron",
        "mail.log",
        "boot.log",
        "dmesg",
        "wtmp",
        "btmp",
        "lastlog",
    ]

    LOG_EXTENSIONS = [".evtx", ".log"]

    def __init__(
        self,
        image_path: str,
        output_dir: str,
        size_limit_mb: int = 50,
        evtx_format: str = "json",
        detect_encoding: bool = True,
        deduplicate: bool = True,
    ):
        self.image_path = image_path
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.size_limit_bytes = size_limit_mb * 1024 * 1024
        self.evtx_format = evtx_format
        self.detect_encoding = detect_encoding
        self.deduplicate = deduplicate

        self.image_type = self._detect_image_type()
        self.partitions = self._get_partitions()

        self.logs_dir = self.output_dir / "logs"
        self.windows_evtx_dir = self.logs_dir / "windows" / "evtx"
        self.windows_other_dir = self.logs_dir / "windows" / "other"
        self.linux_dir = self.logs_dir / "linux"

        for d in [self.windows_evtx_dir, self.windows_other_dir, self.linux_dir]:
            d.mkdir(parents=True, exist_ok=True)

        self._extracted_hashes: Dict[str, str] = {}

    def _detect_image_type(self) -> str:
        ext = Path(self.image_path).suffix.lower()
        if ext in [".e01", ".ewf"]:
            return "ewf"
        return "raw"

    def _run_command(
        self, cmd: List[str], capture: bool = True, timeout: int = 300
    ) -> Tuple[int, str, str]:
        try:
            if capture:
                result = subprocess.run(
                    cmd, capture_output=True, text=True, timeout=timeout
                )
                return result.returncode, result.stdout, result.stderr
            else:
                result = subprocess.run(cmd, timeout=timeout)
                return result.returncode, "", ""
        except subprocess.TimeoutExpired:
            return -1, "", "Command timed out"
        except FileNotFoundError:
            return -1, "", f"Command not found: {cmd[0]}"
        except Exception as e:
            return -1, "", str(e)

    def _get_partitions(self) -> List[Dict]:
        cmd = ["mmls"]
        if self.image_type == "ewf":
            cmd.extend(["-i", "ewf"])
        cmd.append(self.image_path)

        code, stdout, stderr = self._run_command(cmd)
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

    def _get_fls_cmd_base(self, sector_offset: int) -> List[str]:
        cmd = ["fls"]
        if self.image_type == "ewf":
            cmd.extend(["-i", "ewf"])
        cmd.extend(["-o", str(sector_offset)])
        return cmd

    def _detect_filesystem(self, offset: int = 0) -> Optional[str]:
        cmd = self._get_fls_cmd_base(offset)
        cmd.append(self.image_path)

        code, stdout, stderr = self._run_command(cmd)
        if code == 0 and stdout:
            return "auto"

        for fs in ["ntfs", "fat", "ext2", "ext3", "ext4", "hfs", "apfs"]:
            cmd = self._get_fls_cmd_base(offset)
            cmd.extend(["-f", fs])
            cmd.append(self.image_path)

            code, stdout, stderr = self._run_command(cmd)
            if code == 0:
                return fs
        return "ntfs"

    def _parse_fls_line(
        self, line: str, dir_stack: Optional[List[str]] = None
    ) -> Optional[Dict]:
        if not line.strip():
            return None

        indent_level = 0
        for char in line:
            if char == "+":
                indent_level += 1
            else:
                break

        content = line[indent_level:].strip()
        if not content:
            return None

        tab_parts = content.split("\t")
        if len(tab_parts) < 2:
            return None

        main_part = tab_parts[0]
        name = tab_parts[1] if len(tab_parts) > 1 else ""

        space_parts = main_part.split()
        if len(space_parts) < 2:
            return None

        type_str = space_parts[0]
        inode_info = space_parts[1].rstrip(":")

        size = 0
        if len(tab_parts) >= 7:
            try:
                size = int(tab_parts[6])
            except (ValueError, IndexError):
                pass

        inode_parts = inode_info.split("-")
        inode = inode_parts[0] if inode_parts else "0"

        is_allocated = "*" not in line[: indent_level + 2]
        file_type = "file" if "r/r" in type_str else "directory"

        return {
            "type": type_str,
            "inode": inode,
            "size": size,
            "path": name,
            "name": name,
            "is_allocated": is_allocated,
            "file_type": file_type,
            "indent_level": indent_level,
        }

    def _is_log_file(self, path: str) -> Tuple[bool, str]:
        path_lower = path.lower()
        path_normalized = path_lower.replace("\\", "/")

        if path_lower.endswith(".evtx"):
            for log_path in self.WINDOWS_LOG_PATHS:
                if log_path in path_normalized:
                    return True, "evtx"
            return False, ""

        for log_path in self.WINDOWS_LOG_PATHS:
            if log_path in path_normalized:
                if path_lower.endswith(".log"):
                    return True, "windows"
                for specific in self.SPECIFIC_LOG_FILES:
                    if specific in path_lower:
                        return True, "windows"
                return False, ""

        if "var/log/" in path_normalized:
            return True, "linux"

        filename = Path(path).name.lower()
        for specific in self.SPECIFIC_LOG_FILES:
            if specific == filename:
                if "windows" in path_normalized:
                    return True, "windows"
                elif "var/log" in path_normalized:
                    return True, "linux"
                return False, ""

        return False, ""

    def discover_logs(self, partition_num: int = 0) -> List[LogEntry]:
        logs = []
        offset = self._get_partition_offset(partition_num)
        fs_type = self._detect_filesystem(offset)

        cmd = self._get_fls_cmd_base(offset)
        cmd.extend(["-r", "-l"])
        if fs_type and fs_type != "auto":
            cmd.extend(["-f", fs_type])
        cmd.append(self.image_path)

        code, stdout, stderr = self._run_command(cmd, timeout=600)

        if code != 0 or not stdout:
            return logs

        dir_stack: List[str] = []

        for line in stdout.split("\n"):
            parsed = self._parse_fls_line(line)
            if not parsed:
                continue

            indent = parsed.get("indent_level", 0)
            name = parsed.get("name", "")

            while len(dir_stack) > indent:
                dir_stack.pop()

            if parsed["file_type"] == "directory" and name:
                if len(dir_stack) == indent:
                    dir_stack.append(name)
                continue

            full_path = parsed["path"]
            if dir_stack and indent > 0:
                path_parts = dir_stack[:indent]
                if name:
                    full_path = "/".join(path_parts) + "/" + name

            is_log, log_type = self._is_log_file(full_path)
            if not is_log:
                continue

            if parsed["size"] > self.size_limit_bytes:
                continue

            logs.append(
                LogEntry(
                    inode=parsed["inode"],
                    path=full_path,
                    size=parsed["size"],
                    file_type=log_type,
                    partition=partition_num,
                    is_allocated=parsed["is_allocated"],
                )
            )

        return logs

    def _get_partition_offset(self, partition_num: int) -> int:
        if partition_num < len(self.partitions):
            return self.partitions[partition_num].get("start_int", 0)
        return 0

    def extract_log(self, entry: LogEntry, output_path: Path) -> bool:
        offset = self._get_partition_offset(entry.partition)

        cmd = ["icat"]
        if self.image_type == "ewf":
            cmd.extend(["-i", "ewf"])
        cmd.extend(["-o", str(offset), self.image_path, entry.inode])

        try:
            with open(output_path, "wb") as f:
                result = subprocess.run(
                    cmd, stdout=f, stderr=subprocess.PIPE, timeout=120
                )
                return result.returncode == 0
        except Exception as e:
            return False

    def _convert_evtx_to_json(
        self, evtx_path: Path
    ) -> Tuple[List[Dict], Optional[str]]:
        events = []
        error = None

        try:
            import Evtx.Evtx as Evtx

            with Evtx.Evtx(str(evtx_path)) as log:
                for record in log.records():
                    try:
                        xml_data = record.xml()
                        event = self._parse_evtx_xml(xml_data)
                        if event:
                            events.append(event)
                    except Exception:
                        continue

        except ImportError:
            error = "python-evtx not installed. Install with: pip install python-evtx"
            try:
                result = subprocess.run(
                    ["python", "-m", "Evtx.Evtx", str(evtx_path)],
                    capture_output=True,
                    text=True,
                    timeout=120,
                )
                if result.returncode == 0:
                    return self._parse_evtx_output(result.stdout), None
            except Exception as e:
                error = str(e)
        except Exception as e:
            error = f"Error parsing evtx: {str(e)}"

        return events, error

    def _parse_evtx_xml(self, xml_data: str) -> Optional[Dict]:
        import xml.etree.ElementTree as ET

        try:
            root = ET.fromstring(xml_data)

            ns = {"ev": "http://schemas.microsoft.com/win/2004/08/events/event"}

            event_id_elem = root.find(".//ev:EventID", ns)
            event_id = event_id_elem.text if event_id_elem is not None else None

            time_created = root.find(".//ev:TimeCreated", ns)
            timestamp = (
                time_created.get("SystemTime") if time_created is not None else None
            )

            computer = root.find(".//ev:Computer", ns)
            computer_name = computer.text if computer is not None else None

            channel = root.find(".//ev:Channel", ns)
            channel_name = channel.text if channel is not None else None

            level = root.find(".//ev:Level", ns)
            level_name = level.text if level is not None else None

            level_map = {
                "0": "LogAlways",
                "1": "Critical",
                "2": "Error",
                "3": "Warning",
                "4": "Information",
                "5": "Verbose",
            }
            level_name = (
                level_map.get(level_name, level_name) if level_name else "Information"
            )

            event_data = {}
            event_data_elem = root.find(".//ev:EventData", ns)
            if event_data_elem is not None:
                for data in event_data_elem.findall(".//ev:Data", ns):
                    name = data.get("Name", "")
                    value = data.text or ""
                    event_data[name] = value

            return {
                "EventID": int(event_id) if event_id else None,
                "Timestamp": timestamp,
                "Computer": computer_name,
                "Channel": channel_name,
                "Level": level_name,
                "EventData": event_data,
                "RawXml": xml_data,
            }
        except Exception:
            return None

    def _parse_evtx_output(self, output: str) -> List[Dict]:
        events = []
        for line in output.split("\n"):
            if line.strip():
                events.append({"raw": line})
        return events

    def _detect_text_encoding(self, data: bytes) -> str:
        if data.startswith(b"\xef\xbb\xbf"):
            return "utf-8-sig"
        elif data.startswith(b"\xff\xfe"):
            return "utf-16-le"
        elif data.startswith(b"\xfe\xff"):
            return "utf-16-be"

        encodings = ["utf-8", "utf-16", "latin-1", "cp1252", "ascii"]
        for enc in encodings:
            try:
                data.decode(enc)
                return enc
            except UnicodeDecodeError:
                continue
        return "utf-8"

    def _compute_hash(self, file_path: Path) -> str:
        import hashlib

        sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha256.update(chunk)
        return sha256.hexdigest()

    def _sanitize_filename(self, path: str) -> str:
        filename = Path(path).name
        filename = re.sub(r'[<>:"/\\|?*]', "_", filename)
        filename = filename.strip(". ")
        return filename or "unnamed_log"

    def _determine_output_path(self, entry: LogEntry) -> Tuple[Path, str]:
        filename = self._sanitize_filename(entry.path)

        if entry.file_type == "evtx":
            if self.evtx_format == "json":
                return self.windows_evtx_dir / f"{filename}.json", "json"
            return self.windows_evtx_dir / filename, "evtx"
        elif entry.file_type == "windows":
            return self.windows_other_dir / filename, "log"
        elif entry.file_type == "linux":
            return self.linux_dir / filename, "log"
        else:
            if any(
                p in entry.path.lower() for p in ["windows", "winnt", "program files"]
            ):
                return self.windows_other_dir / filename, "log"
            elif any(p in entry.path.lower() for p in ["var/log", "/log", "syslog"]):
                return self.linux_dir / filename, "log"
            return self.logs_dir / filename, "log"

    def extract_all(self, progress_callback=None) -> ExtractionReport:
        report = ExtractionReport(
            image=self.image_path,
            extraction_time=datetime.now(timezone.utc)
            .isoformat()
            .replace("+00:00", "Z"),
            by_type={"evtx": 0, "log": 0, "txt": 0},
        )

        if progress_callback:
            progress_callback(5, "log_discovery", "Scanning for log files...")

        all_logs = []
        for i in range(len(self.partitions)):
            logs = self.discover_logs(i)
            all_logs.extend(logs)

        report.total_logs_found = len(all_logs)

        if progress_callback:
            progress_callback(
                10, "log_extraction", f"Found {len(all_logs)} log files, extracting..."
            )

        total = len(all_logs)
        for idx, entry in enumerate(all_logs):
            if progress_callback and idx % 10 == 0:
                percent = 10 + int((idx / total) * 80) if total > 0 else 50
                progress_callback(
                    percent, "log_extraction", f"Extracting log {idx + 1}/{total}..."
                )

            output_path, out_format = self._determine_output_path(entry)

            counter = 1
            original_path = output_path
            while output_path.exists():
                stem = original_path.stem
                suffix = original_path.suffix
                output_path = original_path.parent / f"{stem}_{counter}{suffix}"
                counter += 1

            temp_path = output_path.with_suffix(".tmp")
            success = self.extract_log(entry, temp_path)

            if not success:
                report.errors.append(
                    {
                        "file": entry.path,
                        "inode": entry.inode,
                        "error": "Failed to extract file",
                    }
                )
                continue

            if self.deduplicate:
                file_hash = self._compute_hash(temp_path)
                if file_hash in self._extracted_hashes:
                    temp_path.unlink()
                    continue
                self._extracted_hashes[file_hash] = entry.path

            if entry.file_type == "evtx" and self.evtx_format == "json":
                events, error = self._convert_evtx_to_json(temp_path)
                if error:
                    report.errors.append(
                        {
                            "file": entry.path,
                            "inode": entry.inode,
                            "error": error,
                        }
                    )
                    output_path = temp_path.with_suffix(".evtx")
                    temp_path.rename(output_path)
                else:
                    temp_path.unlink()
                    with open(output_path, "w", encoding="utf-8") as f:
                        json.dump(events, f, indent=2, ensure_ascii=False)
                    report.by_type["evtx"] += 1
            else:
                if self.detect_encoding and temp_path.exists():
                    try:
                        data = temp_path.read_bytes()
                        encoding = self._detect_text_encoding(data)
                        text = data.decode(encoding)
                        temp_path.unlink()
                        with open(output_path, "w", encoding="utf-8") as f:
                            f.write(text)
                    except Exception:
                        temp_path.rename(output_path)
                else:
                    temp_path.rename(output_path)

                ext = output_path.suffix.lower()
                if ext == ".evtx":
                    report.by_type["evtx"] += 1
                elif ext == ".txt":
                    report.by_type["txt"] += 1
                else:
                    report.by_type["log"] += 1

            report.total_logs_extracted += 1
            report.extracted_files.append(str(output_path.relative_to(self.output_dir)))

            if output_path.exists():
                report.total_size_mb += output_path.stat().st_size / (1024 * 1024)

        if progress_callback:
            progress_callback(95, "log_finalizing", "Saving extraction report...")

        report_file = self.output_dir / "extraction_report.json"
        with open(report_file, "w") as f:
            json.dump(asdict(report), f, indent=2)

        return report


def main():
    parser = argparse.ArgumentParser(
        description="Log File Extractor - Extract and convert log files from disk images",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s image.dd -o output_logs
  %(prog)s image.E01 -o output_logs --evtx-format json
  %(prog)s image.dd -o output_logs --size-limit 100

Library usage:
  from log_extractor import LogExtractor
  extractor = LogExtractor("image.E01", "output")
  report = extractor.extract_all()
        """,
    )
    parser.add_argument("image", help="Path to disk image file")
    parser.add_argument(
        "-o",
        "--output",
        default="logs_output",
        help="Output directory (default: logs_output)",
    )
    parser.add_argument(
        "--size-limit",
        type=int,
        default=50,
        help="Maximum file size in MB to extract (default: 50)",
    )
    parser.add_argument(
        "--evtx-format",
        choices=["json", "binary"],
        default="json",
        help="Output format for evtx files (default: json)",
    )
    parser.add_argument(
        "--no-dedup",
        action="store_true",
        help="Disable deduplication of identical log files",
    )
    parser.add_argument(
        "--no-encoding-detect",
        action="store_true",
        help="Disable automatic text encoding detection",
    )

    args = parser.parse_args()

    if not os.path.exists(args.image):
        print(f"Error: Image file not found: {args.image}")
        sys.exit(1)

    extractor = LogExtractor(
        args.image,
        args.output,
        size_limit_mb=args.size_limit,
        evtx_format=args.evtx_format,
        detect_encoding=not args.no_encoding_detect,
        deduplicate=not args.no_dedup,
    )

    print(f"Processing image: {args.image}")
    print(f"Output directory: {args.output}")
    print(f"Found {len(extractor.partitions)} partitions")

    print("Extracting log files...")
    report = extractor.extract_all()

    print(f"\nExtraction complete:")
    print(f"  Total logs found: {report.total_logs_found}")
    print(f"  Total logs extracted: {report.total_logs_extracted}")
    print(f"  Total size: {report.total_size_mb:.2f} MB")
    print(f"  By type: {report.by_type}")

    if report.errors:
        print(f"\n  Errors: {len(report.errors)}")
        for err in report.errors[:5]:
            print(f"    - {err['file']}: {err['error']}")

    print(f"\nReport saved to: {args.output}/extraction_report.json")


if __name__ == "__main__":
    main()
