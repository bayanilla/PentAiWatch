"""The README shows every setting with its default. Keep it true."""
import json
import os
import unittest

from pentaiwatch.config import Config

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class ReadmeTests(unittest.TestCase):
    def test_settings_shown_in_the_readme_are_the_defaults(self):
        with open(os.path.join(ROOT, "README.md"), encoding="utf-8") as fh:
            text = fh.read()
        block = text.split("```json\n", 1)[1].split("\n```", 1)[0]
        self.assertEqual(json.loads(block), Config().settings())


if __name__ == "__main__":
    unittest.main()
