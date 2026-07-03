from pathlib import Path

# Root directory
BASE_DIR = Path(__file__).resolve().parent.parent

# main folders 
DATA_DIR =  BASE_DIR / "data"
RAW_DIR = DATA_DIR / "raw"
CLEAN = DATA_DIR / "cleaned"