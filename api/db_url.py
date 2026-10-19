# db_url.py
"""
Normalisation des URL PostgreSQL : pilote psycopg2 explicite.

SQLAlchemy 2.1 a changé le pilote par défaut du schéma `postgresql://`
(psycopg2 → psycopg 3). `requirements.txt` n'ayant pas de borne haute, un
simple rebuild de l'image (2026-10-19) a installé SQLAlchemy 2.1.5 et l'API ne
démarrait plus (« No module named 'psycopg' ») : l'image n'embarque que
`psycopg2-binary`. On force donc `postgresql+psycopg2://` quel que soit
l'endroit d'où vient l'URL (DATABASE_URL de api/.env, POSTGRES_*, rôle
applicatif). Une URL portant déjà un pilote explicite est laissée telle quelle.
"""


def with_psycopg2(url: str) -> str:
    if not url:
        return url
    for prefix in ('postgresql://', 'postgres://'):
        if url.startswith(prefix):
            return 'postgresql+psycopg2://' + url[len(prefix):]
    return url
