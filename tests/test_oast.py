from __future__ import annotations

import json
import os
import time
from pathlib import Path

from websec_agent.tools.oast import OastChannel

FAKE_CLIENT = """#!/usr/bin/env python3
import json
import sys
import time

print("[INF] fakepayload0123456789ab.oast.live", flush=True)
time.sleep(0.5)
interaction = {
    "protocol": "http",
    "unique-id": "fakepayload0123456789ab",
    "full-id": "fakepayload0123456789ab",
    "raw-request": "GET /x HTTP/1.1\\r\\nHost: fakepayload0123456789ab.oast.live\\r\\n\\r\\n",
    "raw-response": "HTTP/1.1 200 OK\\r\\n\\r\\n",
    "remote-address": "1.2.3.4",
    "timestamp": "2026-10-31T00:00:00Z",
}
print(json.dumps(interaction), flush=True)
time.sleep(30)
"""


def test_oast_channel_start_poll_stop(tmp_path):
    binary = tmp_path / "interactsh-client"
    binary.write_text(FAKE_CLIENT)
    binary.chmod(0o755)
    log_path = tmp_path / "oast" / "channel.log"

    channel = OastChannel(binary=binary, log_path=log_path)
    assert channel.available
    assert channel.url is None

    assert channel.start() is True
    assert channel.url == "fakepayload0123456789ab.oast.live"

    # interaction appears in the log shortly after startup
    deadline = time.time() + 10
    interactions: list[dict] = []
    while time.time() < deadline and not interactions:
        interactions = channel.new_interactions()
        if not interactions:
            time.sleep(0.2)
    assert interactions, "no interaction parsed from the log"
    assert interactions[0]["protocol"] == "http"
    assert interactions[0]["remote-address"] == "1.2.3.4"

    # dedup: polling again returns nothing new
    assert channel.new_interactions() == []

    total = channel.stop()
    assert total == 1


def test_oast_channel_missing_binary(tmp_path):
    channel = OastChannel(binary=tmp_path / "nope", log_path=tmp_path / "oast" / "channel.log")
    assert channel.available is False
    assert channel.start() is False
    assert channel.url is None
    assert channel.new_interactions() == []
    assert channel.stop() == 0
