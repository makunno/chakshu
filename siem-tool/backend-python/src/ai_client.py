"""
AI Client Utility for SOC Analyst LLM
"""

import os
import sys
from typing import Optional

# OpenRouter model configuration
SOC_MODEL = "google/gemini-2.0-flash-001"
_soc_openrouter_client = None


def get_soc_client():
    """Get or create OpenRouter client for SOC Analyst"""
    global _soc_openrouter_client
    if _soc_openrouter_client is None:
        api_key = os.environ.get("OPENROUTER_API_KEY")
        if api_key:
            # Add imageProcessor path to sys.path
            img_proc_path = os.path.abspath(
                os.path.join(os.path.dirname(__file__), "..", "..", "imageProcessor")
            )
            if img_proc_path not in sys.path:
                sys.path.insert(0, img_proc_path)
            try:
                from ai_forensic_analyzer import OpenRouterClient

                _soc_openrouter_client = OpenRouterClient(api_key, SOC_MODEL)
            except ImportError as e:
                print(f"Warning: Could not import OpenRouterClient: {e}")
    return _soc_openrouter_client
