"""Проверяет, что все четыре лабораторные запускаются как отдельные CLI."""

import subprocess
import sys
import unittest


MODULES = (
    "security_labs.lab1_rsa",
    "security_labs.lab2_kuznyechik",
    "security_labs.lab3_streebog",
    "security_labs.lab4_signature",
)


class ConsoleEntryPointTests(unittest.TestCase):
    def test_help_for_every_lab(self):
        for module in MODULES:
            completed = subprocess.run([sys.executable, "-m", module, "--help"], capture_output=True, text=True, check=False)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertIn("usage:", completed.stdout.lower())

    def test_demo_for_every_lab(self):
        for module in MODULES:
            completed = subprocess.run([sys.executable, "-m", module, "demo"], capture_output=True, text=True, check=False)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertTrue(completed.stdout.strip())
