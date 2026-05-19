#!/usr/bin/env python3
"""
Complete Forensic Analysis Pipeline
Runs: Extraction -> Layered Correlation -> Timestomping -> Anti-Forensic -> Preprocessing -> AI Analysis
"""

import os
import sys
import json
import re
import argparse
from pathlib import Path
from datetime import datetime

# Import our modules
from forensic_extractor import ForensicExtractor
from ai_preprocessor import ForensicPreprocessor
from ai_forensic_analyzer import AIForensicAnalyzer


def run_pipeline(
    image_path: str,
    output_dir: str,
    api_key: str = None,
    model: str = None,
    skip_extraction: bool = False,
    ollama_url: str = "http://localhost:11434",
):
    """Run the complete forensic analysis pipeline."""

    # Use hardcoded Ollama model if not specified
    if model is None:
        model = "google/gemini-2.0-flash-001"

    print("=" * 60)
    print("   FORENSIC ANALYSIS PIPELINE")
    print("=" * 60)

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    layered_results = None
    timestomp_results = None
    advanced_results = None
    preprocessed_data = None
    ai_results = None
    copied_files = []

    # Step 1: Extract artifacts
    if not skip_extraction:
        print("\n[*] STEP 1: Extracting forensic artifacts...")
        print(f"    Image: {image_path}")
        print(f"    Output: {output_dir}")

        extractor = ForensicExtractor(image_path, output_dir)
        result = extractor.extract_everything()

        print(f"    Found {len(result['partitions'])} partitions")
        print(f"    Extracted files saved to: {output_dir}")
    else:
        print("\n[*] STEP 1: Skipping extraction (using existing data)")

    # Step 2: Layered Correlation Engine
    print("\n[*] STEP 2: Running Layered Correlation Engine...")
    try:
        from layered_correlation_engine import run_layered_analysis_for_all_partitions

        layered_results = run_layered_analysis_for_all_partitions(output_dir)

        # Consolidate findings from all partitions
        if "findings" not in layered_results or not layered_results["findings"]:
            all_f = []
            for part in layered_results.get("partition_results", []):
                res = part.get("result", {})
                all_f.extend(res.get("findings", []))
            layered_results["findings"] = all_f

        layered_json = output_path / "layered_analysis_results.json"
        with open(layered_json, "w") as f:
            json.dump(layered_results, f, indent=2, default=str)

        print(
            f"    Analyzed {layered_results.get('analysis_summary', {}).get('total_files_analyzed', 0)} files"
        )
        print(
            f"    Suspicious files: {layered_results.get('analysis_summary', {}).get('suspicious_files', 0)}"
        )
    except Exception as e:
        print(f"    [!] Error in layered correlation: {e}")
        layered_results = {"error": str(e), "findings": [], "analysis_summary": {}}

    # Step 3: Timestomping Detection
    print("\n[*] STEP 3: Running Timestomping Detection...")
    try:
        from hardcoded_timestomp_detector import run_hardcoded_detection

        timestomp_results = run_hardcoded_detection(output_dir)

        from hardcoded_report_generator import generate_reports

        reports = generate_reports(output_dir, timestomp_results)

        print(
            f"    Detected {timestomp_results.get('summary', {}).get('total_suspicious', 0)} suspicious files"
        )
    except Exception as e:
        print(f"    [!] Error in timestomping detection: {e}")
        timestomp_results = {"error": str(e), "summary": {}, "suspicious_files": []}

    # Step 4: Advanced Anti-Forensic Detection
    print("\n[*] STEP 4: Running Advanced Anti-Forensic Detection...")
    try:
        from analyze_antiforensic import AntiForensicAnalyzer

        af_analyzer = AntiForensicAnalyzer(output_dir)
        advanced_results = af_analyzer.analyze()

        advanced_json = output_path / "advanced_antiforensic_results.json"
        with open(advanced_json, "w") as f:
            json.dump(advanced_results, f, indent=2, default=str)

        print(
            f"    Timestomped files: {advanced_results.get('summary', {}).get('timestomped_files', 0)}"
        )
    except Exception as e:
        print(f"    [!] Error in anti-forensic detection: {e}")
        advanced_results = {"error": str(e), "summary": {}, "findings": []}

    # Step 5: AI Preprocessing
    print("\n[*] STEP 5: Running AI Preprocessing...")
    try:
        preprocessor = ForensicPreprocessor(output_dir)
        preprocessed_data = preprocessor.run_full_preprocessing()

        preprocessed_json = output_path / "preprocessed_for_ai.json"
        with open(preprocessed_json, "w") as f:
            json.dump(preprocessed_data, f, indent=2, default=str)

        print(
            f"    Processed {preprocessed_data.get('statistics', {}).get('total_files_processed', 0)} files"
        )
    except Exception as e:
        print(f"    [!] Error in preprocessing: {e}")
        preprocessed_data = {"error": str(e), "statistics": {}}

    # Step 6: AI Analysis
    if api_key or ollama_url:
        print(f"\n[*] STEP 6: Running AI Forensic Intelligence Analysis...")
        print(f"    Model: {model}")
        print(f"    Ollama URL: {ollama_url}")

        try:
            analyzer = AIForensicAnalyzer(output_dir, api_key, model, ollama_url)
            ai_results = analyzer.analyze(preprocessed_data)

            ai_json = output_path / "ai_analysis_results.json"
            with open(ai_json, "w") as f:
                json.dump(ai_results, f, indent=2, default=str)

            # Generate HTML report
            analyzer.generate_html_report(ai_results)

            print(f"    AI Summary: {ai_results.get('summary', 'N/A')}")
            print(f"    Risk Level: {ai_results.get('risk_level', 'N/A')}")
        except Exception as e:
            print(f"    [!] Error in AI analysis: {e}")
            ai_results = {"error": str(e), "summary": "Error during AI analysis"}
    else:
        print("\n[*] STEP 6: Skipping AI Analysis (No API key)")

    # Extract copied files from possiblyCopied.txt
    print("\n[*] STEP 7: Extracting copied files data...")
    copied_path = output_path / "possiblyCopied.txt"
    if copied_path.exists():
        content = copied_path.read_text(errors="ignore")
        for line in content.split("\n"):
            if (
                line.startswith("=")
                or line.startswith("Total")
                or line.startswith("Filename")
                or not line.strip()
            ):
                continue
            dates = re.findall(r"\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}", line)
            if len(dates) >= 2:
                idx = line.find(dates[0])
                if idx >= 0:
                    filename = line[:idx].strip()
                    created = dates[0]
                    modified = dates[1]
                    if filename and len(filename) > 1:
                        copied_files.append(
                            {
                                "filename": filename,
                                "created": created,
                                "modified": modified,
                                "source": "Modified < Created (possibly external)",
                                "destination": "Local",
                            }
                        )

    copied_data = (
        {"files": copied_files, "count": len(copied_files)} if copied_files else None
    )

    # Compile comprehensive results
    all_results = {
        "layered_analysis": layered_results,
        "timestomping": timestomp_results,
        "advanced_analysis": advanced_results,
        "ai_analysis": ai_results,
        "copied_files": copied_data,
        "output_directory": output_dir,
        "analyzed_at": datetime.now().isoformat(),
    }

    print("\n" + "=" * 60)
    print("   PIPELINE COMPLETE")
    print("=" * 60)
    print(f"\nOutput files in {output_dir}:")
    print(f"  - ai_analysis_results.json  (structured results)")
    print(f"  - ai_forensic_report.html   (HTML report)")
    print(f"  - layered_analysis_results.json")
    print(f"  - timestomp_report.json")
    print(f"  - advanced_antiforensic_results.json")

    return all_results


def main():
    parser = argparse.ArgumentParser(
        description="Complete Forensic Analysis Pipeline",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run full pipeline with disk image
  python run_forensic_pipeline.py /path/to/disk image.E01 -o output

  # Use OpenRouter API key
  python run_forensic_pipeline.py image.E01 -k "sk-..." -m "google/gemini-2.0-flash-001"

  # Use local Ollama
  python run_forensic_pipeline.py image.E01 -o output --ollama-url http://localhost:11434 --model glm-5:cloud

  # Skip extraction (use existing data)
  python run_forensic_pipeline.py -o existing_output --skip-extraction
        """,
    )
    parser.add_argument("input", help="Disk image file OR existing output directory")
    parser.add_argument(
        "-o",
        "--output",
        default="forensic_output",
        help="Output directory (default: forensic_output)",
    )
    parser.add_argument(
        "-k", "--api-key", help="OpenRouter API key (or set OPENROUTER_API_KEY env var)"
    )
    parser.add_argument(
        "-m",
        "--model",
        default="glm-5:cloud",
        help="AI model to use (default: glm-5:cloud)",
    )
    parser.add_argument(
        "--ollama-url",
        default="http://localhost:11434",
        help="Ollama URL (default: http://localhost:11434)",
    )
    parser.add_argument(
        "--skip-extraction",
        action="store_true",
        help="Skip extraction, use existing data",
    )

    args = parser.parse_args()

    # Get API key from args or environment
    api_key = args.api_key or os.environ.get("OPENROUTER_API_KEY")

    # Determine if input is image or existing output
    input_path = Path(args.input)

    if input_path.exists() and input_path.is_file():
        # It's an image file
        image_path = str(input_path)
        output_dir = args.output
        skip_extraction = False
    elif input_path.exists() and input_path.is_dir():
        # It's an output directory
        image_path = None
        output_dir = str(input_path)
        skip_extraction = True
    else:
        print(f"[!] Error: Input not found: {args.input}")
        return 1

    # Run pipeline
    try:
        run_pipeline(
            image_path=image_path,
            output_dir=output_dir,
            api_key=api_key,
            model=args.model,
            skip_extraction=skip_extraction,
            ollama_url=args.ollama_url,
        )
    except Exception as e:
        print(f"[!] Error: {e}")
        import traceback

        traceback.print_exc()
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
