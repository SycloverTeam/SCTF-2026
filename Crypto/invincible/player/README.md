# Attachment Notes

This directory is the player attachment for the web JWT challenge.

Included:

- application source files
- templates
- static files
- dependency list
- a database snapshot containing only the admin row
- the same web-facing runtime code used by the server deployment copy

Not included:

- non-admin live database contents
- signing private key
- server-side runtime state
- organizer notes

The intended behavior files are kept identical between `player/` and `server/`:

- `main.py`
- `vuln_jwt.py`
- `vuln_hash.py`
- `templates/`
- `static/`
- `requirements.txt`

The included `data/app.db` only keeps the admin record.
