"""Start PentAIWatch's upload page and open it in the browser: ``python start_upload_page.py``
(or the Run Python File button in VS Code). Stop it with Ctrl+C."""
import sys

from pentaiwatch.cli import main

if __name__ == "__main__":
    sys.exit(main(["serve", "--open", *sys.argv[1:]]))
