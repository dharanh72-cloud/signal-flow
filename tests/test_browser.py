"""End-to-end dashboard check in a real browser.

Skipped automatically unless Playwright and its Chromium build are installed:
    python -m pip install -e ".[browser]" && python -m playwright install chromium
"""

import os
import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

import pytest

pytest.importorskip("playwright")
from playwright.sync_api import sync_playwright  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]


def _free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@pytest.fixture(scope="module")
def server():
    port = _free_port()
    process = subprocess.Popen(
        [sys.executable, str(ROOT / "src" / "app.py")],
        env={**os.environ, "PORT": str(port)},
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    url = f"http://127.0.0.1:{port}"
    try:
        for _ in range(60):
            try:
                urllib.request.urlopen(url + "/healthz", timeout=1)
                break
            except OSError:
                time.sleep(0.5)
        else:
            pytest.fail("dashboard server did not start")
        yield url
    finally:
        process.terminate()
        process.wait(timeout=10)


@pytest.fixture(scope="module")
def browser():
    with sync_playwright() as playwright:
        try:
            instance = playwright.chromium.launch()
        except Exception as error:  # browser binary not installed
            pytest.skip(f"Chromium unavailable: {error}")
        yield instance
        instance.close()


def _wait_for_text(page, selector, predicate, timeout=40):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            value = page.inner_text(selector).strip()
            if predicate(value):
                return value
        except Exception:
            pass
        time.sleep(0.3)
    pytest.fail(f"timed out waiting for {selector}")


@pytest.mark.parametrize("viewport", [{"width": 1440, "height": 900}, {"width": 390, "height": 844}])
def test_sample_analysis_renders_without_errors_or_sideways_scroll(server, browser, viewport):
    page = browser.new_page(viewport=viewport)
    errors = []
    page.on("pageerror", lambda error: errors.append(str(error)))
    page.on("console", lambda msg: errors.append(msg.text) if msg.type == "error" else None)
    page.goto(server + "/?sample=with_attacks.pcap")

    assert _wait_for_text(page, "#metric-flows", str.isdigit) == "142"
    assert page.inner_text("#metric-anomalies").strip() == "62"
    assert page.evaluate("() => document.documentElement.scrollWidth") <= viewport["width"]

    page.locator("tbody tr").first.click()
    assert page.evaluate("() => !!document.querySelector('dialog[open]')")
    assert errors == []
    page.close()

def test_low_confidence_warning_appears_on_the_synthetic_sample(server, browser):
    page = browser.new_page()
    page.goto(server + "/?sample=with_attacks.pcap")
    _wait_for_text(page, "#metric-flows", str.isdigit)
    warning = page.locator("#mix-warning")
    warning.wait_for(state="visible", timeout=10_000)
    assert "low-confidence" in warning.inner_text()
    page.close()

