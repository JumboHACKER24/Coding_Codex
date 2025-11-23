import hashlib
from pathlib import Path

from modules.hash import hash_file


def test_hash_sample_file():
    repo_root = Path(__file__).resolve().parents[1]
    sample_path = repo_root / 'sample_files' / 'sample.txt'
    data = sample_path.read_bytes()
    expected = hashlib.sha256(data).hexdigest()
    assert hash_file(str(sample_path)) == expected
