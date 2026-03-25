"""
Black Duck Detect scan runner.

Downloads and executes the Black Duck Detect CLI (``detect10.sh``) to perform
SCA scans.  Scans run asynchronously as subprocesses with their stdout/stderr
captured into a bounded ring buffer for later retrieval.
"""

from __future__ import annotations

import asyncio
import logging
import os
import stat
import urllib.request
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

logger = logging.getLogger(__name__)

DETECT_SCRIPT_URL = "https://detect.blackduck.com/detect10.sh"
DETECT_DIR = Path.home() / ".blackduck" / "detect"
DETECT_SCRIPT = DETECT_DIR / "detect10.sh"

MAX_LOG_LINES = 500


@dataclass
class ScanRecord:
    """In-memory record tracking a single Detect scan."""

    scan_id: str
    status: str  # STARTING, RUNNING, COMPLETED, FAILED
    source_path: str
    project_name: str | None = None
    version_name: str | None = None
    started_at: str = ""
    finished_at: str | None = None
    return_code: int | None = None
    command_preview: str = ""
    log_lines: deque[str] = field(default_factory=lambda: deque(maxlen=MAX_LOG_LINES))
    _process: asyncio.subprocess.Process | None = field(
        default=None, repr=False,
    )
    _task: asyncio.Task | None = field(default=None, repr=False)

    def to_summary(self) -> dict:
        return {
            "scan_id": self.scan_id,
            "status": self.status,
            "source_path": self.source_path,
            "project_name": self.project_name,
            "version_name": self.version_name,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "return_code": self.return_code,
        }

    def to_detail(self, tail: int = 50) -> dict:
        lines = list(self.log_lines)
        return {
            **self.to_summary(),
            "log_tail": lines[-tail:] if tail else lines,
            "total_log_lines": len(lines),
            "command_preview": self.command_preview,
        }


def _redact_token(args: list[str]) -> str:
    """Build a command preview string with the API token redacted."""
    redacted = []
    for arg in args:
        if arg.startswith("--blackduck.api.token="):
            redacted.append("--blackduck.api.token=***REDACTED***")
        else:
            redacted.append(arg)
    return " ".join(redacted)


class DetectRunner:
    """Manages downloading, executing, and tracking Black Duck Detect scans."""

    def __init__(self) -> None:
        self._scans: dict[str, ScanRecord] = {}

    # ── Setup ────────────────────────────────────────────────────

    async def ensure_detect_available(self) -> Path:
        """Download detect10.sh if not already present. Returns the script path."""
        if DETECT_SCRIPT.exists():
            return DETECT_SCRIPT

        DETECT_DIR.mkdir(parents=True, exist_ok=True)
        logger.info("Downloading Detect script from %s", DETECT_SCRIPT_URL)

        def _download() -> None:
            urllib.request.urlretrieve(DETECT_SCRIPT_URL, DETECT_SCRIPT)  # noqa: S310
            # Make executable
            st = os.stat(DETECT_SCRIPT)
            os.chmod(DETECT_SCRIPT, st.st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)

        await asyncio.to_thread(_download)
        logger.info("Detect script saved to %s", DETECT_SCRIPT)
        return DETECT_SCRIPT

    @staticmethod
    async def check_java() -> str | None:
        """Check Java availability. Returns version string or None."""
        try:
            proc = await asyncio.create_subprocess_exec(
                "java", "-version",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            _, stderr = await proc.communicate()
            if proc.returncode == 0:
                return stderr.decode(errors="replace").strip().split("\n")[0]
            return None
        except FileNotFoundError:
            return None

    # ── Arg building ─────────────────────────────────────────────

    @staticmethod
    def _build_args(
        script_path: Path,
        blackduck_url: str,
        blackduck_token: str,
        source_path: str,
        *,
        project_name: str | None = None,
        version_name: str | None = None,
        scan_mode: str | None = None,
        detect_tools: str | None = None,
        search_depth: int | None = None,
        code_location_name: str | None = None,
        tls_verify: bool = True,
        additional_args: list[str] | None = None,
    ) -> list[str]:
        args = [
            "bash",
            str(script_path),
            f"--blackduck.url={blackduck_url}",
            f"--blackduck.api.token={blackduck_token}",
            f"--detect.source.path={source_path}",
        ]

        if project_name:
            args.append(f"--detect.project.name={project_name}")
        if version_name:
            args.append(f"--detect.project.version.name={version_name}")
        if scan_mode:
            args.append(f"--detect.blackduck.scan.mode={scan_mode}")
        if detect_tools:
            args.append(f"--detect.tools={detect_tools}")
        if search_depth is not None:
            args.append(f"--detect.detector.search.depth={search_depth}")
        if code_location_name:
            args.append(f"--detect.code.location.name={code_location_name}")
        if not tls_verify:
            args.append("--blackduck.trust.cert=true")

        if additional_args:
            for arg in additional_args:
                args.append(arg)

        return args

    # ── Scan execution ───────────────────────────────────────────

    async def start_scan(
        self,
        blackduck_url: str,
        blackduck_token: str,
        source_path: str,
        *,
        project_name: str | None = None,
        version_name: str | None = None,
        scan_mode: str | None = None,
        detect_tools: str | None = None,
        search_depth: int | None = None,
        code_location_name: str | None = None,
        tls_verify: bool = True,
        additional_args: list[str] | None = None,
    ) -> str:
        """Start a Detect scan. Returns the scan_id."""
        # Validate source path
        src = Path(source_path).resolve()
        if not src.exists():
            raise FileNotFoundError(f"Source path does not exist: {src}")

        # Validate additional_args
        if additional_args:
            for arg in additional_args:
                if not arg.startswith("--"):
                    raise ValueError(
                        f"Invalid additional argument: '{arg}'. "
                        "All arguments must start with '--' (e.g. --detect.cleanup=false)."
                    )

        # Validate scan_mode
        if scan_mode and scan_mode.upper() not in ("INTELLIGENT", "RAPID"):
            raise ValueError(
                f"Invalid scan_mode: '{scan_mode}'. Must be INTELLIGENT or RAPID."
            )

        # Check Java
        java_version = await self.check_java()
        if java_version is None:
            raise RuntimeError(
                "Java is not available on this system. "
                "Black Duck Detect requires Java 17 or later. "
                "Please install Java and ensure 'java' is on your PATH."
            )

        # Ensure detect script is downloaded
        script_path = await self.ensure_detect_available()

        # Build args
        args = self._build_args(
            script_path,
            blackduck_url,
            blackduck_token,
            str(src),
            project_name=project_name,
            version_name=version_name,
            scan_mode=scan_mode.upper() if scan_mode else None,
            detect_tools=detect_tools,
            search_depth=search_depth,
            code_location_name=code_location_name,
            tls_verify=tls_verify,
            additional_args=additional_args,
        )

        scan_id = uuid4().hex[:12]
        now = datetime.now(timezone.utc).isoformat()

        record = ScanRecord(
            scan_id=scan_id,
            status="STARTING",
            source_path=str(src),
            project_name=project_name,
            version_name=version_name,
            started_at=now,
            command_preview=_redact_token(args),
        )
        self._scans[scan_id] = record

        # Start subprocess
        proc = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            cwd=str(src),
        )
        record._process = proc
        record.status = "RUNNING"

        # Spawn background task to capture output
        record._task = asyncio.create_task(self._capture_output(record))

        logger.info("Started Detect scan %s (pid=%s)", scan_id, proc.pid)
        return scan_id

    async def _capture_output(self, record: ScanRecord) -> None:
        """Read process output line by line until exit."""
        proc = record._process
        assert proc is not None
        assert proc.stdout is not None

        try:
            async for raw_line in proc.stdout:
                line = raw_line.decode(errors="replace").rstrip("\n")
                record.log_lines.append(line)
        except Exception:
            logger.exception("Error reading output for scan %s", record.scan_id)

        return_code = await proc.wait()
        record.return_code = return_code
        record.finished_at = datetime.now(timezone.utc).isoformat()
        record.status = "COMPLETED" if return_code == 0 else "FAILED"
        logger.info(
            "Detect scan %s finished with return code %s",
            record.scan_id,
            return_code,
        )

    # ── Status queries ───────────────────────────────────────────

    def get_scan_status(self, scan_id: str, log_lines: int = 50) -> dict:
        """Get the status and log tail for a scan."""
        record = self._scans.get(scan_id)
        if record is None:
            raise KeyError(f"No scan found with id '{scan_id}'")
        return record.to_detail(tail=log_lines)

    def list_scans(self) -> list[dict]:
        """List all tracked scans (summary only)."""
        return [r.to_summary() for r in self._scans.values()]
