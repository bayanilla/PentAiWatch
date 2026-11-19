"""The upload page: ``python -m pentaiwatch serve`` (after VulnScope MAX's upload page).

Pages and calls (routes.py):
  GET  /                      the upload page (upload.py)
  POST /analyze-folder        analyze a folder on this computer in place
  POST /analyze               analyze uploaded files (multipart, streamed to disk)
  POST /browse, /pick-folder  the folder list, or the macOS folder dialog (folders.py)
  POST /folder-kind           whether a folder is a finished report's output folder (reopened, not analyzed)
  GET  /runs/<id>/            a run: progress while it runs, then its results (runs.py)
  GET  /runs/<id>/status      its state, for the progress overlay
  GET  /runs/<id>/<file>      its report, Explorer and other files, in a sandbox

Each run gets a folder under the runs folder: in/ (uploads, or SOURCE.txt for a folder read in
place), out/ (the usual results) and STATUS.json. Safety checks: handler.py.
"""
