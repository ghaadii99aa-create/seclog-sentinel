"""WSGI entry point: gunicorn wsgi:app"""

from seclog.web import create_app

app = create_app()
