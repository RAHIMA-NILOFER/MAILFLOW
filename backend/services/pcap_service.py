"""
PCAP Analysis Service for MailFlow Sentinel
Handles analysis storage, active session lookup, and pipeline orchestration.
"""
import os
import shutil
from typing import Dict, Optional
from backend.models.schemas import PCAPAnalysis
from backend.services.demo_service import generate_demo_analysis
from backend.analyzers.pcap_parser import parse_pcap_file

# In-memory storage for analysis results
ANALYSIS_STORE: Dict[str, PCAPAnalysis] = {}

def get_or_create_demo_analysis() -> PCAPAnalysis:
    """Retrieve or initialize standard demo forensic analysis."""
    demo_id = "ANALYSIS-DEMO-001"
    if demo_id not in ANALYSIS_STORE:
        ANALYSIS_STORE[demo_id] = generate_demo_analysis()
    return ANALYSIS_STORE[demo_id]

def get_analysis_by_id(analysis_id: str) -> Optional[PCAPAnalysis]:
    """Retrieve an analysis by its ID."""
    if analysis_id == "ANALYSIS-DEMO-001" or analysis_id == "demo" or analysis_id == "latest":
        return get_or_create_demo_analysis()
    return ANALYSIS_STORE.get(analysis_id) or get_or_create_demo_analysis()

def process_uploaded_pcap(temp_file_path: str, original_filename: str) -> PCAPAnalysis:
    """Run passive forensic analysis pipeline on uploaded PCAP file."""
    analysis = parse_pcap_file(temp_file_path, original_filename)
    ANALYSIS_STORE[analysis.id] = analysis
    # Also set as latest
    ANALYSIS_STORE["latest"] = analysis
    return analysis
