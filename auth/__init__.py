# auth/__init__.py
# Exposes the FastAPI router for registration in main.py
from auth.router import router as auth_router  # noqa: F401
