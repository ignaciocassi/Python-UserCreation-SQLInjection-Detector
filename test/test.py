import unittest
from flask import json
from index import InjectionPreventionServer

class TestInjectionPreventionServer(unittest.TestCase):
    def setUp(self):
        self.server = InjectionPreventionServer()
        self.app = self.server.app
        self.client = self.app.test_client()
        self.app.config['TESTING'] = True

    def test_add_user_legit(self):
        response = self.client.post('/add_user', data=json.dumps({
            'username': 'ignacioCassi',
            'email': 'ignacio@gmail.com',
            'password': 'Mess1!!!'
        }), content_type='application/json')
        print(response.get_data(as_text=True))
        self.assertEqual(response.status_code, 200)
        self.assertIn('correctamente', response.get_data(as_text=True))

    def test_add_user_legit(self):
        response = self.client.post('/add_user', data=json.dumps({
            'username': 'Nahuel',
            'email': 'ignacio@gmail.com',
            'password': 'Mess1!!!'
        }), content_type='application/json')
        print(response.get_data(as_text=True))
        self.assertEqual(response.status_code, 200)
        self.assertIn('correctamente', response.get_data(as_text=True))

    def test_add_user_legit(self):
        response = self.client.post('/add_user', data=json.dumps({
            'username': 'Caro',
            'email': 'caro@gmail.com',
            'password': 'Mess1!!!'
        }), content_type='application/json')
        print(response.get_data(as_text=True))
        self.assertEqual(response.status_code, 200)
        self.assertIn('correctamente', response.get_data(as_text=True))


    def test_add_user_sql_injection_username(self):
        response = self.client.post('/add_user', data=json.dumps({
            'username': 'romanBorla-- OR 1 == 1',
            'email': 'roman@gmail.com',
            'password': 'Ronaldo!!!'
        }), content_type='application/json')
        print(response.get_data(as_text=True))
        self.assertEqual(response.status_code, 400)
        self.assertIn('Alerta: Intento de iny', response.get_data(as_text=True))


    def test_add_user_sql_injection_email(self):
        response = self.client.post('/add_user', data=json.dumps({
            'username': 'matiasRoca',
            'email': 'mat-- OR 1 == 1ias@gmail.com',
            'password': 'Mbappe!!!'
        }), content_type='application/json')
        print(response.get_data(as_text=True))
        self.assertEqual(response.status_code, 400)
        self.assertIn('The email address contains invalid characters', response.get_data(as_text=True))


if __name__ == '__main__':
    unittest.main()