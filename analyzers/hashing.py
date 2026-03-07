"""
MD5 / SHA1 / SHA256 / SHA512 Hashing.
"""
import hashlib
from pathlib import Path
from models.schemas import HashResult


def compute_hashes(file_path: Path) -> HashResult:
    """Alle 4 Hashes in einem Durchlauf berechnen."""
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    sha512 = hashlib.sha512()

    file_size = 0
    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            file_size += len(chunk)
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
            sha512.update(chunk)

    return HashResult(
        md5=md5.hexdigest(),
        sha1=sha1.hexdigest(),
        sha256=sha256.hexdigest(),
        sha512=sha512.hexdigest(),
        file_size_bytes=file_size,
    )
