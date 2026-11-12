"""Reviewed renderer provisioning for explicitly isolated native framework CI only."""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import platform
import shutil
import ssl
import stat
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import zipfile
from pathlib import Path, PurePosixPath

VERSION = "157.0.8103.78"
INDEX_URL = (
	"https://googlechromelabs.github.io/chrome-for-testing/last-known-good-versions-with-downloads.json"
)
DOWNLOAD_URL = (
	f"https://storage.googleapis.com/chrome-for-testing-public/{VERSION}/linux64/chrome-linux64.zip"
)
ARCHIVE_SHA256 = "9223832977a13db3646201b1341c1f9cf08afa3ceae92540116d7b0c062364fb"
EXECUTABLE_SHA256 = "f60cb86024464df9740504a1584b605c2b3cf107625ff11e1da22c875c1627e8"
RELATIVE_ROOT = Path("ais-pdf-renderers") / VERSION
EXECUTABLE = Path("chrome-linux64/chrome")
ARCHIVE_NAME = "reviewed-download.zip"
MAX_ARCHIVE_BYTES = 350 * 1024 * 1024
MAX_UNPACKED_BYTES = 1024 * 1024 * 1024
MAX_FILES = 5000


class NoRedirect(urllib.request.HTTPRedirectHandler):
	def redirect_request(self, request, fp, code, msg, headers, newurl):
		raise urllib.error.HTTPError(request.full_url, code, "Unexpected vendor redirect", headers, fp)


def _platform_check() -> None:
	if platform.system() != "Linux" or platform.machine() != "x86_64":
		raise RuntimeError("Reviewed deployment renderer requires Linux x86_64")


def _digest(path: Path) -> str:
	with path.open("rb") as source:
		return hashlib.file_digest(source, "sha256").hexdigest()


def _safe_root(bench: Path) -> Path:
	bench = bench.resolve(strict=True)
	if not bench.is_dir():
		raise RuntimeError("Expected an existing Bench directory")
	root = bench / RELATIVE_ROOT
	for parent in (root.parent, root):
		if parent.is_symlink():
			raise RuntimeError("Renderer directory cannot be a symlink")
	return root


def _opener():
	# The app declares certifi's reviewed CA bundle. Never disable TLS verification,
	# follow redirects, or inherit an arbitrary proxy for a privileged build download.
	import certifi

	context = ssl.create_default_context(cafile=certifi.where())
	return urllib.request.build_opener(
		urllib.request.ProxyHandler({}), NoRedirect, urllib.request.HTTPSHandler(context=context)
	)


def _download(opener, url: str, output, *, limit: int) -> None:
	started = time.monotonic()
	request = urllib.request.Request(url, headers={"User-Agent": "AIS-reviewed-renderer-build/1"})
	with opener.open(request, timeout=60) as response:
		if response.geturl() != url or response.status != 200:
			raise RuntimeError("Unexpected vendor response")
		length = response.headers.get("Content-Length")
		if length is not None and (not length.isdecimal() or int(length) > limit):
			raise RuntimeError("Vendor download exceeds the allowed size")
		total = 0
		while chunk := response.read(1024 * 1024):
			total += len(chunk)
			if total > limit or time.monotonic() - started > 300:
				raise RuntimeError("Vendor download exceeds build limits")
			output.write(chunk)


def _validate_index(payload: bytes) -> None:
	stable = json.loads(payload)["channels"]["Stable"]
	if stable["version"] != VERSION or not any(
		entry["platform"] == "linux64" and entry["url"] == DOWNLOAD_URL
		for entry in stable["downloads"]["chrome"]
	):
		raise RuntimeError("Reviewed renderer is no longer the official stable Linux64 release")


def _entries(bundle: zipfile.ZipFile) -> tuple[zipfile.ZipInfo, ...]:
	entries = tuple(bundle.infolist())
	if not entries or len(entries) > MAX_FILES:
		raise RuntimeError("Unexpected vendor archive entry count")
	total = 0
	seen = set()
	for entry in entries:
		name = entry.filename.rstrip("/")
		parts = name.split("/")
		path = PurePosixPath(name)
		kind = stat.S_IFMT(entry.external_attr >> 16)
		if (
			not name
			or "\\" in name
			or path.is_absolute()
			or any(part in ("", ".", "..") for part in parts)
			or parts[0] != "chrome-linux64"
			or len(parts) > 12
			or name in seen
			or entry.flag_bits & 1
			or kind not in (0, stat.S_IFDIR, stat.S_IFREG)
			or (kind == stat.S_IFDIR and not entry.is_dir())
			or (kind == stat.S_IFREG and entry.is_dir())
		):
			raise RuntimeError("Unsafe vendor archive entry")
		seen.add(name)
		total += entry.file_size
		if total > MAX_UNPACKED_BYTES or entry.file_size > MAX_UNPACKED_BYTES:
			raise RuntimeError("Vendor archive exceeds unpacked size limit")
	return entries


def _extract(archive: Path, destination: Path) -> None:
	with zipfile.ZipFile(archive) as bundle:
		for entry in _entries(bundle):
			target = destination / entry.filename
			if entry.is_dir():
				target.mkdir(parents=True, exist_ok=True)
				target.chmod(0o755)
				continue
			target.parent.mkdir(parents=True, exist_ok=True)
			with bundle.open(entry) as source, target.open("xb") as output:
				shutil.copyfileobj(source, output, length=1024 * 1024)
			target.chmod(0o755 if (entry.external_attr >> 16) & 0o111 else 0o644)


def _verify_installation(root: Path) -> dict[str, str]:
	if root.is_symlink() or not root.is_dir() or root.stat().st_mode & 0o7022:
		raise RuntimeError("Renderer root directory permissions are unsafe")
	archive = root / ARCHIVE_NAME
	if archive.is_symlink() or not archive.is_file() or _digest(archive) != ARCHIVE_SHA256:
		raise RuntimeError("Reviewed renderer archive hash mismatch")
	# Retain the hash-pinned archive as the authority for shared libraries/resources
	# too; an editable sidecar manifest must not authenticate altered dependencies.
	with zipfile.ZipFile(archive) as bundle:
		entries = _entries(bundle)
		expected = set()
		for entry in entries:
			target = root / entry.filename
			expected.add(target)
			expected.update(parent for parent in target.parents if parent != root and root in parent.parents)
			if target.is_symlink():
				raise RuntimeError("Renderer contains a symlink")
			if entry.is_dir():
				if not target.is_dir():
					raise RuntimeError("Renderer directory is missing")
				continue
			if not target.is_file() or target.stat().st_size != entry.file_size:
				raise RuntimeError("Renderer file is missing or has changed size")
			with bundle.open(entry) as source:
				if hashlib.file_digest(source, "sha256").hexdigest() != _digest(target):
					raise RuntimeError("Renderer resource hash mismatch")
			mode = target.stat().st_mode
			expected_exec = bool((entry.external_attr >> 16) & 0o111)
			if mode & 0o022 or bool(mode & 0o111) != expected_exec or mode & 0o7000:
				raise RuntimeError("Renderer file permissions changed")
		actual = set(root.rglob("*"))
		if actual != expected | {archive}:
			raise RuntimeError("Renderer directory contains unexpected files")
		for path in expected:
			if path.is_symlink() or (path.is_dir() and path.stat().st_mode & 0o7022):
				raise RuntimeError("Renderer parent directory permissions are unsafe")
	executable = root / EXECUTABLE
	if executable.is_symlink() or not executable.is_file() or _digest(executable) != EXECUTABLE_SHA256:
		raise RuntimeError("Reviewed renderer executable hash mismatch")
	version = subprocess.check_output([str(executable), "--version"], text=True, timeout=15).strip()
	if version.split()[-1:] != [VERSION]:
		raise RuntimeError("Reviewed renderer executable version mismatch")
	return {
		"version": VERSION,
		"path": str(executable),
		"archive_sha256": ARCHIVE_SHA256,
		"executable_sha256": EXECUTABLE_SHA256,
	}


def provision(bench: Path) -> dict[str, str]:
	"""Install a reviewed renderer atomically in the image; called only by opt-in build hook."""
	_platform_check()
	root = _safe_root(bench)
	root.parent.mkdir(mode=0o755, exist_ok=True)
	lock_fd = os.open(root.parent / ".install.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
	try:
		fcntl.flock(lock_fd, fcntl.LOCK_EX)
		# Require a current vendor stable confirmation even on an idempotent rebuild.
		opener = _opener()
		with tempfile.SpooledTemporaryFile(max_size=1024 * 1024) as index:
			_download(opener, INDEX_URL, index, limit=1024 * 1024)
			index.seek(0)
			_validate_index(index.read())
		if root.exists():
			result = _verify_installation(root)
		else:
			with tempfile.TemporaryDirectory(prefix=".renderer-build-", dir=root.parent) as temporary:
				staging = Path(temporary) / VERSION
				staging.mkdir(mode=0o755)
				archive = staging / ARCHIVE_NAME
				with archive.open("xb") as output:
					_download(opener, DOWNLOAD_URL, output, limit=MAX_ARCHIVE_BYTES)
				if _digest(archive) != ARCHIVE_SHA256:
					raise RuntimeError("Downloaded renderer archive hash mismatch")
				_extract(archive, staging)
				_verify_installation(staging)
				staging.rename(root)
			result = _verify_installation(root)
		print("AIS_PDF_RENDERER_BUILD=" + json.dumps(result, sort_keys=True))
		return result
	finally:
		os.close(lock_fd)


def verify_configured_renderer(bench: Path, configured_path: object) -> dict[str, str]:
	"""Local-only fail-closed verification before migration, never a provisioning fallback."""
	_platform_check()
	root = _safe_root(bench)
	expected = root / EXECUTABLE
	if not isinstance(configured_path, str) or configured_path != str(expected):
		raise RuntimeError(f"chromium_path must explicitly select {expected}")
	result = _verify_installation(root)
	print("AIS_PDF_RENDERER_VERIFIED=" + json.dumps(result, sort_keys=True))
	return result


def _isolated_native_ci() -> tuple[Path, Path]:
	if (
		os.environ.get("CI") != "Yes"
		or os.environ.get("GITHUB_ACTIONS") != "true"
		or os.environ.get("AIS_PDFKIT_FREE_PROTOTYPE") != "Yes"
	):
		raise RuntimeError("Renderer provisioning requires explicit isolated native Actions CI opt-in")
	_platform_check()
	bench = Path.cwd().resolve(strict=True)
	workspace = Path(os.environ["GITHUB_WORKSPACE"]).resolve(strict=True)
	if bench != workspace or not all(
		(bench / relative).is_dir() for relative in ("apps/frappe", "sites/test_site", "env")
	):
		raise RuntimeError("Native renderer provisioning requires the exact disposable Actions Bench")
	if not (bench / "sites/test_site/site_config.json").is_file():
		raise RuntimeError("Disposable test_site configuration is missing")
	temporary = Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)
	if not temporary.is_dir():
		raise RuntimeError("Expected an existing Actions temporary directory")
	return bench, temporary / "ais-native-renderer-proof.json"


def main() -> None:
	if len(sys.argv) != 1:
		raise RuntimeError("Native renderer helper accepts no path or download overrides")
	bench, proof = _isolated_native_ci()
	if proof.exists() or proof.is_symlink():
		raise RuntimeError("Native renderer proof must be newly created")
	result = provision(bench)
	verify_configured_renderer(bench, result["path"])
	with proof.open("x") as output:
		json.dump(result, output, sort_keys=True)
		output.write("\n")
	print("AIS_NATIVE_CI_RENDERER_PROOF=" + json.dumps(result, sort_keys=True))


if __name__ == "__main__":
	main()
