"""
Forensic Analysis Background Task Manager
Handles async execution of the forensic pipeline with progress tracking.
"""

import os
import sys
import json
import uuid
import threading
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, Optional
from enum import Enum
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv(os.path.join(os.path.dirname(__file__), ".env"))

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "imageProcessor"))

try:
    from run_forensic_pipeline import run_pipeline

    FORENSIC_PIPELINE_AVAILABLE = True
except ImportError as e:
    print(f"Warning: Forensic pipeline not available: {e}")
    FORENSIC_PIPELINE_AVAILABLE = False


class TaskStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class ForensicTask:
    def __init__(self, task_id: str, image_path: str):
        self.task_id = task_id
        self.image_path = image_path
        self.status = TaskStatus.PENDING
        self.progress = 0
        self.stage = "initialized"
        self.message = "Task created"
        self.output_dir: Optional[str] = None
        self.results: Optional[Dict[str, Any]] = None
        self.antiforensic_results: Optional[Dict[str, Any]] = None
        self.pdf_path: Optional[str] = None
        self.error: Optional[str] = None
        self.created_at = datetime.now().isoformat()
        self.completed_at: Optional[str] = None


class ForensicTaskManager:
    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._tasks: Dict[str, ForensicTask] = {}
        return cls._instance

    def create_task(self, image_path: str) -> ForensicTask:
        task_id = str(uuid.uuid4())
        task = ForensicTask(task_id, image_path)
        self._tasks[task_id] = task
        return task

    def get_task(self, task_id: str) -> Optional[ForensicTask]:
        return self._tasks.get(task_id)

    def update_task(
        self,
        task_id: str,
        status: TaskStatus = None,
        progress: int = None,
        stage: str = None,
        message: str = None,
        output_dir: str = None,
        results: Dict = None,
        antiforensic_results: Dict = None,
        pdf_path: str = None,
        error: str = None,
    ):
        task = self._tasks.get(task_id)
        if not task:
            return

        if status:
            task.status = status
        if progress is not None:
            task.progress = progress
        if stage:
            task.stage = stage
        if message:
            task.message = message
        if output_dir:
            task.output_dir = output_dir
        if results:
            task.results = results
        if antiforensic_results:
            task.antiforensic_results = antiforensic_results
        if pdf_path:
            task.pdf_path = pdf_path
        if error:
            task.error = error

        if status == TaskStatus.COMPLETED or status == TaskStatus.FAILED:
            task.completed_at = datetime.now().isoformat()

    def run_forensic_analysis(
        self, task_id: str, image_path: str, output_base_dir: str = None
    ):
        task = self.get_task(task_id)
        if not task:
            return

        try:
            self.update_task(
                task_id,
                status=TaskStatus.RUNNING,
                progress=5,
                stage="validation",
                message="Validating image file...",
            )

            image_file = Path(image_path)
            if not image_file.exists():
                self.update_task(
                    task_id,
                    status=TaskStatus.FAILED,
                    error=f"Image file not found: {image_path}",
                )
                return

            ext = image_file.suffix.lower()
            if ext not in [".e01", ".dd", ".raw", ".img"]:
                self.update_task(
                    task_id,
                    status=TaskStatus.FAILED,
                    error=f"Unsupported image format: {ext}. Supported: .e01, .dd, .raw, .img",
                )
                return

            self.update_task(
                task_id,
                progress=10,
                stage="preparation",
                message="Preparing output directory...",
            )

            if output_base_dir is None:
                output_base_dir = os.path.join(
                    os.path.dirname(__file__), "..", "forensic_output"
                )

            safe_name = (
                image_file.stem.replace(" ", "_").replace("/", "_").replace("\\", "_")
            )
            output_dir = os.path.join(output_base_dir, safe_name)
            os.makedirs(output_dir, exist_ok=True)

            self.update_task(task_id, progress=15, output_dir=output_dir)

            api_key = os.environ.get("OPENROUTER_API_KEY")
            if not api_key:
                self.update_task(
                    task_id,
                    status=TaskStatus.FAILED,
                    error="OPENROUTER_API_KEY environment variable not set. Please configure it on the server.",
                )
                return

            self.update_task(
                task_id,
                progress=20,
                stage="extraction",
                message="Extracting forensic artifacts...",
            )

            progress_callback = lambda p, s, m: self.update_task(
                task_id, progress=p, stage=s, message=m
            )

            self._run_pipeline_with_progress(
                image_path=str(image_file),
                output_dir=output_dir,
                api_key=api_key,
                progress_callback=progress_callback,
                task_id=task_id,
            )

        except Exception as e:
            import traceback

            self.update_task(
                task_id,
                status=TaskStatus.FAILED,
                error=f"Analysis failed: {str(e)}\n{traceback.format_exc()}",
            )

    def _run_pipeline_with_progress(
        self,
        image_path: str,
        output_dir: str,
        api_key: str,
        progress_callback,
        task_id: str,
    ):
        try:
            from forensic_extractor import ForensicExtractor
            from ai_preprocessor import ForensicPreprocessor
            from ai_forensic_analyzer import AIForensicAnalyzer
            from analyze_antiforensic import AntiForensicAnalyzer
            from pdf_report_generator import ForensicPDFReport
            from log_extractor import LogExtractor

            progress_callback(25, "extraction", "Extracting partition information...")

            extractor = ForensicExtractor(image_path, output_dir)
            result = extractor.extract_everything()

            log_extractor = LogExtractor(
                image_path, output_dir, size_limit_mb=50, evtx_format="json"
            )
            log_thread = threading.Thread(
                target=self._extract_logs_thread,
                args=(log_extractor, task_id),
                daemon=True,
            )
            log_thread.start()

            progress_callback(
                45,
                "preprocessing",
                f"Extracted {len(result.get('partitions', []))} partitions. Preprocessing...",
            )

            preprocessor = ForensicPreprocessor(output_dir)
            preprocessed = preprocessor.run_full_preprocessing()

            log_thread.join(timeout=300)

            stats = preprocessed.get("statistics", {})
            progress_callback(
                60,
                "ai_analysis",
                f"Processed {stats.get('total_files_processed', 0)} files. Running AI analysis...",
            )

            analyzer = AIForensicAnalyzer(output_dir, api_key)
            analysis = analyzer.analyze(preprocessed)

            json_file = os.path.join(output_dir, "ai_analysis_results.json")
            with open(json_file, "w") as f:
                json.dump(analysis, f, indent=2, default=str)

            progress_callback(85, "report_generation", "Generating HTML report...")

            analyzer.generate_html_report(analysis)

            progress_callback(
                88, "antiforensic_analysis", "Running anti-forensic analysis..."
            )

            af_analyzer = AntiForensicAnalyzer(output_dir)
            antiforensic_results = af_analyzer.analyze()

            af_json_file = os.path.join(output_dir, "antiforensic_analysis.json")
            with open(af_json_file, "w") as f:
                json.dump(antiforensic_results, f, indent=2)

            progress_callback(94, "pdf_generation", "Generating PDF report...")

            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            pdf_filename = f"forensic_report_{timestamp}.pdf"
            pdf_path = os.path.join(output_dir, pdf_filename)

            pdf_report = ForensicPDFReport(
                output_path=pdf_path,
                image_path=image_path,
                ai_results=analysis,
                antiforensic_results=antiforensic_results,
            )
            pdf_report.generate()

            self.update_task(
                task_id,
                status=TaskStatus.COMPLETED,
                progress=100,
                stage="complete",
                message="Analysis complete",
                results=analysis,
                antiforensic_results=antiforensic_results,
                pdf_path=pdf_path,
            )

        except Exception as e:
            import traceback

            self.update_task(
                task_id,
                status=TaskStatus.FAILED,
                error=f"Pipeline error: {str(e)}\n{traceback.format_exc()}",
            )

    def _extract_logs_thread(self, log_extractor, task_id: str):
        try:
            log_extractor.extract_all()
        except Exception as e:
            pass


task_manager = ForensicTaskManager()
