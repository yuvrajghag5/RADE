from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data"
RAW = DATA / "raw"
CLEAN = DATA / "cleaned"
PROCESSED = DATA / "processed"

# alias kept so existing imports (`from config.paths import RAW_DIR`) keep working
RAW_DIR = RAW
