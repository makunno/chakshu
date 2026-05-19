#!/usr/bin/env python3
"""
Complete Forensic Analysis Pipeline
Runs: Extraction -> Preprocessing -> AI Analysis -> HTML Report
"""

import os
import sys
import json
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
):
    """Run the complete forensic analysis pipeline."""

    print("=" * 60)
    print("   FORENSIC ANALYSIS PIPELINE")
    print("=" * 60)

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

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

    # Step 2: Preprocess
    print("\n[*] STEP 2: Preprocessing for AI analysis...")
    preprocessor = ForensicPreprocessor(output_dir)
    preprocessed = preprocessor.run_full_preprocessing()

    stats = preprocessed.get("statistics", {})
    print(f"    Processed {stats.get('total_files_processed', 0)} files")
    print(f"    Total data: {stats.get('total_size_mb', 0)} MB")

    # Step 3: AI Analysis (if API key provided)
    if api_key:
        print("\n[*] STEP 3: AI Analysis...")
        print(f"    Model: {model or 'meta-llama/llama-3.1-8b-instruct'}")

        analyzer = AIForensicAnalyzer(output_dir, api_key, model)
        analysis = analyzer.analyze(preprocessed)

        # Save JSON results
        json_file = output_path / "ai_analysis_results.json"
        with open(json_file, "w") as f:
            json.dump(analysis, f, indent=2, default=str)
        print(f"    Results saved to: {json_file}")

        # Generate HTML report
        print("\n[*] STEP 4: Generating HTML report...")
        analyzer.generate_html_report(analysis)

        print("\n" + "=" * 60)
        print("   PIPELINE COMPLETE")
        print("=" * 60)
        print(f"\nOutput files in {output_dir}:")
        print(f"  - ai_analysis_results.json  (structured results)")
        print(f"  - ai_forensic_report.html   (HTML report)")

        # Print summary
        if "summary" in analysis:
            print(f"\nAI Summary: {analysis['summary']}")
        if "risk_level" in analysis:
            print(f"Risk Level: {analysis['risk_level']}")

    else:
        print("\n[!] STEP 3: Skipping AI analysis (no API key)")
        print("    To enable AI analysis:")
        print("    1. Get free API key: https://openrouter.ai/settings")
        print("    2. Run: export OPENROUTER_API_KEY=your_key")
        print("    3. Run: python3 ai_forensic_analyzer.py <output_dir>")

        print("\n" + "=" * 60)
        print("   PIPELINE COMPLETE (EXTRACTION + PREPROCESSING)")
        print("=" * 60)

    return True


def main():
    parser = argparse.ArgumentParser(
        description="Complete Forensic Analysis Pipeline",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Full pipeline with API key
  %(prog)s image.dd -o output -k $OPENROUTER_API_KEY
  
  # Skip extraction, just analyze existing data
  %(prog)s existing_output -k $OPENROUTER_API_KEY --skip-extraction
  
  # Custom model
  %(prog)s image.dd -o output -k KEY -m "anthropic/claude-3-haiku"

Get free API key: https://openrouter.ai/settings
Models: https://openrouter.ai/models (look for free ones)
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
        default="meta-llama/llama-3.1-8b-instruct",
        help="AI model to use",
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
        )
    except Exception as e:
        print(f"[!] Error: {e}")
        import traceback

        traceback.print_exc()
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
