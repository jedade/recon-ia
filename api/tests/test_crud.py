# tests/test_crud.py
"""
Tests des endpoints CRUD /recon et /verify_email.

Format de réponse attendu (standardisé) :
  Succès  → {"success": true,  "data": {...}, "message": "..."}
  Liste   → {"success": true,  "data": [...], "total": N, "page": N, "per_page": N, "pages": N}
  Erreur  → {"success": false, "error": "..."}
"""
import pytest
from unittest.mock import patch


class TestCreateRecon:
    def test_missing_field_returns_400(self, client, auth_headers):
        response = client.post('/recon', json={
            'domain': 'example.com',
            'firstname': 'Jean',
            # lastname manquant
            'email': 'jean@example.com',
            'accord': True
        }, headers=auth_headers)
        assert response.status_code == 400
        body = response.get_json()
        assert body['success'] is False
        assert 'lastname' in body['error']

    def test_invalid_domain_returns_400(self, client, auth_headers):
        response = client.post('/recon', json={
            'domain': 'not_a_domain',
            'firstname': 'Jean',
            'lastname': 'Dupont',
            'email': 'jean@example.com',
            'accord': True
        }, headers=auth_headers)
        assert response.status_code == 400
        assert response.get_json()['success'] is False

    def test_invalid_email_returns_400(self, client, auth_headers):
        response = client.post('/recon', json={
            'domain': 'example.com',
            'firstname': 'Jean',
            'lastname': 'Dupont',
            'email': 'not-an-email',
            'accord': True
        }, headers=auth_headers)
        assert response.status_code == 400
        assert response.get_json()['success'] is False

    def test_no_json_returns_400_or_415(self, client, auth_headers):
        response = client.post('/recon', headers=auth_headers)
        assert response.status_code in (400, 415)

    @patch('routes.crud.send_verification_email')
    def test_valid_creation_returns_201(self, mock_email, client, auth_headers):
        mock_email.return_value = True
        response = client.post('/recon', json={
            'domain': 'example.com',
            'firstname': 'Jean',
            'lastname': 'Dupont',
            'email': 'jean@example.com',
            'accord': True
        }, headers=auth_headers)
        assert response.status_code == 201
        body = response.get_json()
        assert body['success'] is True
        assert 'data' in body
        assert body['data']['domain'] == 'example.com'
        assert body['data']['verification'] is False

    @patch('routes.crud.send_verification_email')
    def test_resubmit_while_otp_active_is_throttled(self, mock_email, client, auth_headers):
        """
        Re-soumettre le même email pendant qu'un OTP est encore valide est
        refusé avec 429 (anti-spam d'envoi), et non 400 : l'email n'est pas
        « déjà pris », c'est le renvoi de code qui est temporisé.
        La réponse indique le délai restant via `retry_after_seconds`.
        """
        mock_email.return_value = True
        payload = {
            'domain': 'example.com',
            'firstname': 'Jean',
            'lastname': 'Dupont',
            'email': 'unique@example.com',
            'accord': True
        }
        first = client.post('/recon', json=payload, headers=auth_headers)
        assert first.status_code == 201

        response = client.post('/recon', json=payload, headers=auth_headers)
        assert response.status_code == 429
        body = response.get_json()
        assert body['success'] is False
        assert 'déjà' in body['error']
        assert body['retry_after_seconds'] > 0

    @patch('routes.crud.send_verification_email')
    def test_otp_not_exposed_in_response(self, mock_email, client, auth_headers):
        mock_email.return_value = True
        response = client.post('/recon', json={
            'domain': 'example.com',
            'firstname': 'Jean',
            'lastname': 'Dupont',
            'email': 'nootp@example.com',
            'accord': True
        }, headers=auth_headers)
        body = response.get_json()
        assert 'otp_code' not in body.get('data', {})

    @patch('routes.crud.send_verification_email')
    def test_creation_is_public_no_auth_required(self, mock_email, client):
        """
        POST /recon est le formulaire public de demande d'analyse : il ne porte
        volontairement pas @require_auth (spec Swagger `security: []`).
        Un visiteur non authentifié doit donc pouvoir créer sa demande.
        """
        mock_email.return_value = True
        response = client.post('/recon', json={
            'domain': 'example.com', 'firstname': 'X', 'lastname': 'Y',
            'email': 'noauth@example.com', 'accord': True
        })
        assert response.status_code == 201
        assert response.get_json()['success'] is True


class TestGetRecons:
    def test_returns_paginated_response(self, client, auth_headers):
        response = client.get('/recon', headers=auth_headers)
        assert response.status_code == 200
        body = response.get_json()
        assert body['success'] is True
        assert 'data' in body
        assert 'total' in body
        assert 'page' in body
        assert 'pages' in body

    def test_pagination_params(self, client, auth_headers):
        response = client.get('/recon?page=1&per_page=5', headers=auth_headers)
        assert response.status_code == 200
        body = response.get_json()
        assert body['page'] == 1

    def test_per_page_capped_at_100(self, client, auth_headers):
        response = client.get('/recon?per_page=500', headers=auth_headers)
        assert response.status_code == 200
        body = response.get_json()
        assert body['per_page'] <= 100


class TestGetReconById:
    @patch('routes.crud.send_verification_email')
    def test_get_existing(self, mock_email, client, auth_headers):
        mock_email.return_value = True
        create = client.post('/recon', json={
            'domain': 'example.com',
            'firstname': 'A',
            'lastname': 'B',
            'email': 'ab@example.com',
            'accord': True
        }, headers=auth_headers)
        recon_id = create.get_json()['data']['id']
        response = client.get(f'/recon/{recon_id}', headers=auth_headers)
        assert response.status_code == 200
        body = response.get_json()
        assert body['success'] is True
        assert 'data' in body

    def test_get_nonexistent_returns_404(self, client, auth_headers):
        response = client.get('/recon/99999', headers=auth_headers)
        assert response.status_code == 404


class TestDeleteRecon:
    @patch('routes.crud.send_verification_email')
    def test_delete_existing(self, mock_email, client, auth_headers):
        mock_email.return_value = True
        create = client.post('/recon', json={
            'domain': 'example.com',
            'firstname': 'Del',
            'lastname': 'Me',
            'email': 'delme@example.com',
            'accord': True
        }, headers=auth_headers)
        recon_id = create.get_json()['data']['id']
        response = client.delete(f'/recon/{recon_id}', headers=auth_headers)
        assert response.status_code == 200
        body = response.get_json()
        assert body['success'] is True
        assert body['deleted_id'] == recon_id

    def test_delete_nonexistent_returns_404(self, client, auth_headers):
        response = client.delete('/recon/99999', headers=auth_headers)
        assert response.status_code == 404


class TestUpdateRecon:
    @patch('routes.crud.send_verification_email')
    def test_cannot_set_verification_via_put(self, mock_email, client, auth_headers):
        mock_email.return_value = True
        create = client.post('/recon', json={
            'domain': 'example.com',
            'firstname': 'Test',
            'lastname': 'User',
            'email': 'testuser@example.com',
            'accord': True
        }, headers=auth_headers)
        recon_id = create.get_json()['data']['id']

        response = client.put(f'/recon/{recon_id}', json={
            'verification': True
        }, headers=auth_headers)
        assert response.status_code == 200
        # verification ne doit PAS avoir changé — seul /verify_email peut la modifier
        get_resp = client.get(f'/recon/{recon_id}', headers=auth_headers)
        assert get_resp.get_json()['data']['verification'] is False

    @patch('routes.crud.send_verification_email')
    def test_update_domain_and_firstname(self, mock_email, client, auth_headers):
        mock_email.return_value = True
        create = client.post('/recon', json={
            'domain': 'old.com',
            'firstname': 'Old',
            'lastname': 'Name',
            'email': 'update@example.com',
            'accord': True
        }, headers=auth_headers)
        recon_id = create.get_json()['data']['id']

        response = client.put(f'/recon/{recon_id}', json={
            'domain': 'new.com',
            'firstname': 'New',
        }, headers=auth_headers)
        assert response.status_code == 200
        body = response.get_json()
        assert body['success'] is True
        assert body['data']['domain'] == 'new.com'
        assert body['data']['firstname'] == 'New'


class TestAnonymousOverwriteProtection:
    """
    Régression : POST /recon est anonyme et réinitialisait l'enregistrement
    existant d'un email donné, effaçant scan_results / analysis_result /
    final_report / pdf_report. Connaître un email suffisait donc à détruire
    le rapport d'un tiers sans authentification.
    """

    @patch('routes.crud.send_verification_email')
    def test_verified_record_with_results_is_not_wiped(self, mock_email, client, auth_headers, app):
        mock_email.return_value = True
        from database import db
        from models.recon import Recon

        with app.app_context():
            r = Recon(domain='victime.com', firstname='V', lastname='I',
                      email='victime@example.com', accord=True, verification=True,
                      status='success')
            r.scan_results = '{"dns_records": {"status": "success"}}'
            r.set_analysis_result({'security_score': 88, 'security_grade': 'A'})
            db.session.add(r)
            db.session.commit()
            rid = r.id

        # Requête ANONYME (aucun header d'authentification)
        resp = client.post('/recon', json={
            'domain': 'attaquant.tld', 'firstname': 'x', 'lastname': 'x',
            'email': 'victime@example.com', 'accord': True,
        })
        assert resp.status_code == 201   # réponse indiscernable du cas nominal

        with app.app_context():
            from models.recon import Recon as R
            v = R.query.get(rid)
            assert v.scan_results is not None, 'scan_results a été effacé'
            assert v.analysis_result is not None, 'analysis_result a été effacé'
            assert v.security_score == 88
            assert v.domain == 'victime.com', 'le domaine cible a été détourné'

    @patch('routes.crud.send_verification_email')
    def test_unverified_record_can_still_be_reused(self, mock_email, client, auth_headers):
        """Le parcours légitime (email jamais vérifié) doit rester fonctionnel."""
        mock_email.return_value = True
        payload = {'domain': 'a.com', 'firstname': 'A', 'lastname': 'B',
                   'email': 'reuse@example.com', 'accord': True}
        assert client.post('/recon', json=payload).status_code == 201
