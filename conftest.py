"""pytest configuration — adds project root to sys.path so `engine.*` imports resolve."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
