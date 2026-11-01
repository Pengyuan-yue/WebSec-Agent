"""Headless browser probe for the websec-agent tool layer.

Run as a subprocess: browser_probe.py '<json-spec>'
The spec is validated here as a second scope guardrail: both the initial URL
and the post-action URL must stay on an authorized host, otherwise the page
content is withheld and an error is returned.

Output: a single JSON object on stdout.
"""

from __future__ import annotations

import base64
import json
import re
import sys
from urllib.parse import urlparse

ALLOWED_ACTIONS = {"get", "click", "type", "flow"}
MAX_DOM_CHARS = 20000


def host_allowed(url: str, allowed_hosts: list[str], allow_private: bool) -> bool:
    try:
        parsed = urlparse(url)
    except ValueError:
        return False
    if parsed.scheme not in {"http", "https"}:
        return False
    host = (parsed.hostname or "").lower()
    if not host:
        return False
    for allowed in allowed_hosts:
        allowed = allowed.lower().lstrip(".")
        if host == allowed or host.endswith("." + allowed):
            return True
    if allow_private:
        if host in {"localhost", "localhost.localdomain"} or host.endswith(".localhost"):
            return True
        try:
            import ipaddress

            ip = ipaddress.ip_address(host)
        except ValueError:
            return False
        return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
    return False


def capture(page) -> dict:
    title = ""
    dom_text = ""
    try:
        title = page.title()
    except Exception:
        pass
    try:
        dom_text = page.evaluate(
            "document.body ? document.body.innerText : ''"
        )
        if isinstance(dom_text, str) and len(dom_text) > MAX_DOM_CHARS:
            dom_text = dom_text[:MAX_DOM_CHARS] + "\n[...dom text truncated...]"
    except Exception:
        dom_text = ""
    return {"title": title, "dom_text": dom_text}


def run(spec: dict) -> dict:
    # Sandbox resets wipe /root/.cache; prefer the persistent in-project copy
    # when the harness installed browsers there (tools/setup_browser.sh).
    import os
    from pathlib import Path

    if "PLAYWRIGHT_BROWSERS_PATH" not in os.environ:
        persistent = Path(__file__).resolve().parent / "pw-browsers"
        if persistent.is_dir():
            os.environ["PLAYWRIGHT_BROWSERS_PATH"] = str(persistent)

    from playwright.sync_api import sync_playwright

    action = spec.get("action", "get")
    if action not in ALLOWED_ACTIONS:
        return {"error": f"unsupported action: {action}"}
    url = str(spec.get("url", ""))
    allowed_hosts = [str(h) for h in spec.get("allowed_hosts", [])]
    allow_private = bool(spec.get("allow_private", False))
    if not host_allowed(url, allowed_hosts, allow_private):
        return {"error": f"scope: navigation URL not authorized: {url}"}

    proxy = spec.get("proxy") or None
    if proxy:
        # A loopback/private target must not be routed through an external
        # egress proxy: bypass it so locally deployed targets stay reachable.
        host = (urlparse(url).hostname or "").lower()
        is_local_name = (
            host in {"localhost", "localhost.localdomain"} or host.endswith(".localhost")
        )
        try:
            import ipaddress

            ip = ipaddress.ip_address(host)
            is_local_ip = ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
        except ValueError:
            is_local_ip = False
        if is_local_name or is_local_ip:
            proxy = None
    result: dict = {
        "action": action,
        "requested_url": url,
        "final_url": "",
        "status": None,
        "clicked": None,
        "filled": {},
    }

    with sync_playwright() as pw:
        launch_kwargs = {
            "headless": True,
            "args": ["--no-sandbox", "--disable-dev-shm-usage"],
            "proxy": {"server": proxy} if proxy else None,
        }
        try:
            browser = pw.chromium.launch(**launch_kwargs)
        except Exception:
            # Missing dedicated headless-shell build: fall back to the full
            # chromium binary running in its new headless mode.
            browser = pw.chromium.launch(channel="chromium", **launch_kwargs)
        try:
            page = browser.new_page(
                viewport={"width": 1280, "height": 800},
                user_agent="websec-agent-browser/0.1",
            )
            response = page.goto(url, timeout=30000, wait_until="domcontentloaded")
            if response is not None:
                result["status"] = response.status

            if action == "click":
                selector = str(spec.get("selector", ""))
                if not selector:
                    return {"error": "click action requires 'selector'"}
                page.click(selector, timeout=15000)
                result["clicked"] = selector
            elif action == "type":
                selector = str(spec.get("selector", ""))
                value = str(spec.get("value", ""))
                if not selector:
                    return {"error": "type action requires 'selector'"}
                page.fill(selector, value, timeout=15000)
                result["filled"] = {selector: value}
            elif action == "flow":
                fill = spec.get("fill") or {}
                if isinstance(fill, dict):
                    for selector, value in fill.items():
                        page.fill(str(selector), str(value), timeout=15000)
                        result["filled"][str(selector)] = str(value)
                click_selector = spec.get("click")
                if click_selector:
                    page.click(str(click_selector), timeout=15000)
                    result["clicked"] = str(click_selector)

            page.wait_for_timeout(int(float(spec.get("wait_ms", 1500))))
            page.wait_for_load_state("domcontentloaded", timeout=10000)
            result["final_url"] = page.url
            result.update(capture(page))
            if not host_allowed(result["final_url"], allowed_hosts, allow_private):
                return {
                    "error": (
                        f"scope: post-action URL left the authorized target: {result['final_url']}"
                    ),
                    "final_url": result["final_url"],
                }
            png = page.screenshot(type="png")
            result["screenshot_b64"] = base64.b64encode(png).decode("ascii")
        finally:
            browser.close()
    return result


def main() -> int:
    if len(sys.argv) != 2:
        print(json.dumps({"error": "usage: browser_probe.py '<json-spec>'"}))
        return 2
    try:
        spec = json.loads(sys.argv[1])
    except ValueError as exc:
        print(json.dumps({"error": f"bad spec json: {exc}"}))
        return 2
    try:
        print(json.dumps(run(spec), ensure_ascii=False))
    except Exception as exc:  # noqa: BLE001 - probe must never raise into the harness
        print(json.dumps({"error": f"{type(exc).__name__}: {exc}"}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
