from pathlib import Path
import sys
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from src.scanner import scan_tree

def test_finds_fixture_issues():
    res = scan_tree(ROOT / "fixtures")
    assert res["finding_count"] >= 2

if __name__ == "__main__":
    test_finds_fixture_issues(); print("smoke_ok")
