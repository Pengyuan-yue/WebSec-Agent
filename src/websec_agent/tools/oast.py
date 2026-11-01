from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path
from typing import Any

OAST_URL_RE = re.compile(r"\b([a-z0-9]{20,50}\.oast\.[a-z]{2,})\b")
STARTUP_TIMEOUT_SECONDS = 45.0


class OastChannel:
    """Out-of-band testing channel backed by interactsh-client.

    The client is spawned once per run; it registers with the default OAST
    server cluster, prints a unique callback domain, and streams every
    interaction (DNS/HTTP/SMTP) as JSON lines to a log file. The harness
    polls that file and turns new interactions into OAST_CALLBACK evidence.
    """

    def __init__(self, binary: str | Path, log_path: str | Path) -> None:
        self._binary = Path(binary)
        self._log_path = Path(log_path)
        self._process: subprocess.Popen | None = None
        self._url: str | None = None
        self._seen: set[str] = set()

    @property
    def available(self) -> bool:
        import os

        if self._binary.exists():
            return True
        if os.name == "nt" and self._binary.with_name(self._binary.name + ".exe").exists():
            return True
        return False

    @property
    def url(self) -> str | None:
        return self._url

    def start(self) -> bool:
        """Spawn the client and wait for the callback URL. Never raises."""
        if not self.available or self._process is not None:
            return self._process is not None
        try:
            self._log_path.parent.mkdir(parents=True, exist_ok=True)
            self._log_path.write_text("", encoding="utf-8")
            handle = self._log_path.open("ab")
            import os

            binary = self._binary
            if os.name == "nt" and not binary.exists():
                binary = binary.with_name(binary.name + ".exe")
            try:
                self._process = subprocess.Popen(
                    [str(binary), "-json", "-v"],
                    stdout=handle,
                    stderr=subprocess.STDOUT,
                    stdin=subprocess.DEVNULL,
                )
            finally:
                handle.close()

            import time

            deadline = time.monotonic() + STARTUP_TIMEOUT_SECONDS
            while time.monotonic() < deadline:
                if self._process.poll() is not None:
                    return False
                self._url = self._read_url()
                if self._url:
                    return True
                time.sleep(0.5)
            return False
        except OSError:
            self.stop()
            return False

    def _read_url(self) -> str | None:
        try:
            text = self._log_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return None
        match = OAST_URL_RE.search(text)
        return match.group(1) if match else None

    def new_interactions(self) -> list[dict[str, Any]]:
        """Return interactions not yet returned (dedup by protocol/id/time)."""
        if not self._log_path.exists():
            return []
        fresh: list[dict[str, Any]] = []
        try:
            text = self._log_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return fresh
        for line in text.splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                interaction = json.loads(line)
            except ValueError:
                continue
            if not isinstance(interaction, dict):
                continue
            key = "|".join(
                str(interaction.get(field, ""))
                for field in ("protocol", "unique-id", "timestamp")
            )
            if not key.strip("|"):
                continue
            if key in self._seen:
                continue
            self._seen.add(key)
            fresh.append(interaction)
        return fresh

    def stop(self) -> int:
        """Terminate the client. Returns total interactions observed."""
        process, self._process = self._process, None
        if process is not None:
            try:
                process.terminate()
                process.wait(timeout=10)
            except (OSError, subprocess.TimeoutExpired):
                try:
                    process.kill()
                except OSError:
                    pass
        return len(self._seen)
