# tests/test_auth.py
"""
Tests du décorateur require_auth.

Ces tests ciblent GET /recon, qui est protégé par @require_auth.

Ne PAS utiliser POST /recon ici : c'est le formulaire public de demande
d'analyse (`'security': []` dans sa spec Swagger, aucun @require_auth), il
répond donc 400 sur un corps invalide et jamais 401. Les tests visaient
historiquement cet endpoint et ne validaient donc pas l'authentification.
"""
import pytest


class TestRequireAuth:
    def test_no_auth_returns_401(self, client):
        response = client.get('/recon')
        assert response.status_code == 401

    def test_wrong_password_returns_401(self, client, bad_auth_headers):
        response = client.get('/recon', headers=bad_auth_headers)
        assert response.status_code == 401

    def test_valid_auth_passes(self, client, auth_headers):
        response = client.get('/recon', headers=auth_headers)
        assert response.status_code == 200

    def test_401_includes_www_authenticate_header(self, client):
        """RFC 7235 : une 401 doit porter un en-tête WWW-Authenticate."""
        response = client.get('/recon')
        assert response.status_code == 401
        assert 'WWW-Authenticate' in response.headers

    def test_401_error_message(self, client):
        response = client.get('/recon')
        data = response.get_json()
        assert 'error' in data

    def test_wrong_credentials_no_info_leak(self, client, bad_auth_headers):
        """Le message d'erreur ne doit pas révéler quel facteur est erroné."""
        response = client.get('/recon', headers=bad_auth_headers)
        data = response.get_json()
        assert 'error' in data
        err = data['error'].lower()
        assert 'password' not in err
        assert 'mot de passe' not in err
        assert 'utilisateur' not in err

    def test_public_creation_endpoint_is_not_protected(self, client):
        """
        Garde-fou : POST /recon doit rester public (formulaire visiteur).
        Un 401 ici signifierait qu'on a protégé par erreur le point d'entrée
        public et cassé le parcours de demande d'analyse.
        """
        response = client.post('/recon', json={})
        assert response.status_code != 401
