# tests/test_verify_email.py
import pytest
from unittest.mock import patch
from datetime import datetime, timedelta


class TestVerifyEmail:
    @patch('routes.crud.send_verification_email')
    def _create_recon(self, client, auth_headers, mock_email, email='verify@example.com'):
        mock_email.return_value = True
        resp = client.post('/recon', json={
            'domain': 'example.com',
            'firstname': 'V',
            'lastname': 'E',
            'email': email,
            'accord': True
        }, headers=auth_headers)
        return resp.get_json()['data']

    def test_no_json_returns_400_or_415(self, client, auth_headers):
        response = client.post('/verify_email', headers=auth_headers)
        assert response.status_code in (400, 415)

    def test_missing_fields_returns_400(self, client, auth_headers):
        response = client.post('/verify_email', json={'email': 'a@b.com'}, headers=auth_headers)
        assert response.status_code == 400

    def test_wrong_code_returns_404_or_400(self, client, auth_headers):
        recon = self._create_recon(client, auth_headers)
        response = client.post('/verify_email', json={
            'email': recon['email'],
            'code': '000000'
        }, headers=auth_headers)
        assert response.status_code in (400, 404)

    def test_nonexistent_email_returns_404(self, client, auth_headers):
        response = client.post('/verify_email', json={
            'email': 'nobody@nowhere.com',
            'code': '123456'
        }, headers=auth_headers)
        assert response.status_code == 404

    @patch('routes.crud.send_verification_email')
    def test_valid_code_verifies(self, mock_email, client, auth_headers, app):
        mock_email.return_value = True
        client.post('/recon', json={
            'domain': 'example.com',
            'firstname': 'V',
            'lastname': 'E',
            'email': 'real@example.com',
            'accord': True
        }, headers=auth_headers)

        with app.app_context():
            from models.recon import Recon
            recon = Recon.query.filter_by(email='real@example.com').first()
            code = recon.otp_code

        response = client.post('/verify_email', json={
            'email': 'real@example.com',
            'code': code
        }, headers=auth_headers)
        assert response.status_code == 200
        assert response.get_json()['data']['verification'] is True

    @patch('routes.crud.send_verification_email')
    def test_valid_code_sets_start_report_date(self, mock_email, client, auth_headers, app):
        """La vérification email doit horodater start_report_date."""
        mock_email.return_value = True
        client.post('/recon', json={
            'domain': 'example.com',
            'firstname': 'V',
            'lastname': 'E',
            'email': 'startdate@example.com',
            'accord': True
        }, headers=auth_headers)

        with app.app_context():
            from models.recon import Recon
            recon = Recon.query.filter_by(email='startdate@example.com').first()
            code = recon.otp_code

        response = client.post('/verify_email', json={
            'email': 'startdate@example.com',
            'code': code
        }, headers=auth_headers)
        assert response.status_code == 200
        data = response.get_json()['data']
        assert data['start_report_date'] is not None

    @patch('routes.crud.send_verification_email')
    def test_start_report_date_not_set_before_verification(self, mock_email, client, auth_headers, app):
        """start_report_date doit être None tant que l'email n'est pas vérifié."""
        mock_email.return_value = True
        resp = client.post('/recon', json={
            'domain': 'example.com',
            'firstname': 'V',
            'lastname': 'E',
            'email': 'notverified@example.com',
            'accord': True
        }, headers=auth_headers)
        assert resp.status_code == 201
        assert resp.get_json()['data']['start_report_date'] is None
