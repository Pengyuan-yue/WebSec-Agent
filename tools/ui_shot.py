"""1920x1080 screenshots of the web console (main view + brief modal + finding modal)."""
import asyncio
import sys
from pathlib import Path

from playwright.async_api import async_playwright

OUT = Path("/workspace/websec-agent/artifacts/ui")
OUT.mkdir(parents=True, exist_ok=True)


async def main() -> None:
    async with async_playwright() as pw:
        browser = await pw.chromium.launch(args=["--no-sandbox"])
        page = await browser.new_page(viewport={"width": 1920, "height": 1080})
        await page.goto("http://127.0.0.1:8080/", wait_until="networkidle")
        await page.wait_for_timeout(3500)  # let findings + cached translations render

        await page.screenshot(path=str(OUT / "console_main.png"))
        print("saved main")

        # 漏洞速览 modal
        await page.click("text=漏洞速览")
        await page.wait_for_selector("#overlay.show", timeout=5000)
        await page.wait_for_timeout(2500)  # cached brief loads fast
        await page.screenshot(path=str(OUT / "brief_modal.png"))
        print("saved brief")

        await page.click(".modal-head .x")
        await page.wait_for_timeout(600)

        # finding modal (Chinese, cached translation)
        cards = await page.query_selector_all(".fcard")
        if cards:
            await cards[0].click()
            await page.wait_for_selector("#overlay.show", timeout=5000)
            await page.wait_for_timeout(2500)
            await page.screenshot(path=str(OUT / "finding_modal.png"))
            print("saved finding")

        await browser.close()


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
