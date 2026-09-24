"""Dépendances partagées entre les routes de l'API."""

from app.core.db import get_db

__all__ = ["get_db"]