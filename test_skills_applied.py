"""
test_skills_applied.py
Verifies that all skills (design-md, ui-ux-pro-max, security-appsec-engineer,
engineering-backend-architect, testing-performance-benchmarker) are applied to SABRO VISION.
"""

import os
import sys
import time
import requests
import unittest

BASE_URL = "http://127.0.0.1:8080"

class TestSkillsApplied(unittest.TestCase):

    def test_01_design_md_compliance(self):
        """[design-md] DESIGN.md exists, has valid YAML tokens and all 8 required sections"""
        design_file = os.path.join(os.path.dirname(__file__), "DESIGN.md")
        self.assertTrue(os.path.exists(design_file), "DESIGN.md must exist in project root")

        with open(design_file, "r", encoding="utf-8") as f:
            content = f.read()

        # Check YAML Front Matter
        self.assertTrue(content.startswith("---"), "DESIGN.md must start with YAML front matter delimiter '---'")
        parts = content.split("---", 2)
        self.assertGreaterEqual(len(parts), 3, "DESIGN.md must contain front matter between --- delimiters")
        
        yaml_content = parts[1]
        for key in ["colors:", "typography:", "rounded:", "spacing:", "components:"]:
            self.assertIn(key, yaml_content, f"Front matter must define '{key}' token group")

        # Check 8 Required Sections
        body = parts[2]
        required_sections = [
            "## 1. Overview",
            "## 2. Colors",
            "## 3. Typography",
            "## 4. Layout & Spacing",
            "## 5. Elevation & Depth",
            "## 6. Shapes",
            "## 7. Components",
            "## 8. Do's and Don'ts"
        ]
        for section in required_sections:
            self.assertIn(section, body, f"DESIGN.md must contain mandatory section '{section}'")

    def test_02_ui_ux_accessibility_viewport(self):
        """[ui-ux-pro-max] Viewport allows zooming (WCAG 1.4.4 compliance)"""
        templates_dir = os.path.join(os.path.dirname(__file__), "templates")
        for filename in ["base.html", "tv_player.html"]:
            path = os.path.join(templates_dir, filename)
            with open(path, "r", encoding="utf-8") as f:
                content = f.read()
            self.assertNotIn("user-scalable=no", content, f"{filename} must not disable user zoom")
            self.assertNotIn("maximum-scale=1.0", content, f"{filename} must not restrict max scale")

    def test_03_ui_ux_reduced_motion(self):
        """[ui-ux-pro-max] tv.css supports prefers-reduced-motion"""
        tv_css_path = os.path.join(os.path.dirname(__file__), "static", "css", "tv.css")
        with open(tv_css_path, "r", encoding="utf-8") as f:
            css_content = f.read()
        self.assertIn("prefers-reduced-motion: reduce", css_content, "tv.css must implement prefers-reduced-motion")

    def test_04_appsec_security_headers(self):
        """[security-appsec-engineer] Server returns all required AppSec hardening headers"""
        resp = requests.get(f"{BASE_URL}/gatekeeper", timeout=5)
        self.assertEqual(resp.status_code, 200)

        headers = resp.headers
        self.assertIn("Content-Security-Policy", headers)
        self.assertEqual(headers.get("X-Content-Type-Options"), "nosniff")
        self.assertEqual(headers.get("X-Frame-Options"), "SAMEORIGIN")
        self.assertEqual(headers.get("Referrer-Policy"), "strict-origin-when-cross-origin")
        self.assertIn("Permissions-Policy", headers)
        self.assertEqual(headers.get("Cross-Origin-Opener-Policy"), "same-origin-allow-popups")

    def test_05_backend_health_probe(self):
        """[engineering-backend-architect] /api/health probe returns 200 and healthy JSON"""
        resp = requests.get(f"{BASE_URL}/api/health", timeout=5)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()

        self.assertEqual(data.get("status"), "healthy")
        self.assertEqual(data.get("database"), "connected")
        self.assertIn("uptime_seconds", data)
        self.assertIn("metrics", data)
        self.assertGreater(data["metrics"]["channels_count"], 1000)
        self.assertGreater(data["metrics"]["packages_count"], 0)

    def test_06_performance_latency_benchmark(self):
        """[testing-performance-benchmarker] Health & Core endpoints respond in under 100ms"""
        latencies = []
        for _ in range(5):
            t0 = time.perf_counter()
            resp = requests.get(f"{BASE_URL}/api/health", timeout=5)
            dt = (time.perf_counter() - t0) * 1000.0
            self.assertEqual(resp.status_code, 200)
            latencies.append(dt)

        avg_latency = sum(latencies) / len(latencies)
        print(f"\n  [BENCHMARK] Average /api/health latency: {avg_latency:.2f} ms")
        self.assertLess(avg_latency, 100.0, f"Average latency {avg_latency:.2f}ms should be under 100ms")


if __name__ == "__main__":
    unittest.main()
