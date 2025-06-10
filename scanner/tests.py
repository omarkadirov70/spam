from django.test import TestCase, Client
from unittest.mock import patch
from django.core.files.uploadedfile import SimpleUploadedFile
from django.urls import reverse
import email
from . import utils


class UploadViewTests(TestCase):
    def test_upload_page_loads(self):
        client = Client()
        response = client.get(reverse('upload'))
        self.assertEqual(response.status_code, 200)

    def test_stats_page_loads(self):
        client = Client()
        response = client.get(reverse('stats'))
        self.assertEqual(response.status_code, 200)

    def test_upload_eml(self):
        client = Client()
        eml = b"From: a@example.com\nTo: b@example.com\nSubject: hi\n\nhello"
        file = SimpleUploadedFile('test.eml', eml, content_type='application/octet-stream')
        response = client.post(reverse('upload'), {'msg_file': file})
        self.assertEqual(response.status_code, 200)


class UtilsTests(TestCase):
    def test_parse_headers(self):
        raw = (
            'From: Alice <alice@example.com>\n'
            'Reply-To: reply@example.com\n'
            'Subject: Test\n'
            'Received: by mail.example.com\n\nBody'
        )
        msg = email.message_from_string(raw)
        info = utils.parse_headers(msg)
        self.assertEqual(info['from'], 'Alice <alice@example.com>')
        self.assertEqual(info['reply_to'], 'reply@example.com')
        self.assertEqual(info['subject'], 'Test')
        self.assertEqual(info['received'], ['by mail.example.com'])

    def test_content_filters(self):
        text = 'Get FREE money now! Viagra available.'
        keywords = utils.find_keywords(text)
        self.assertIn('free money', keywords)
        self.assertIn('viagra', keywords)
        freqs = utils.word_frequencies(text, ['free'])
        self.assertEqual(freqs['free'], 1)

    def test_ml_prediction(self):
        with patch('scanner.utils.fetch_training_data') as fake:
            fake.return_value = [
                ('buy cheap meds', 1),
                ('cheap viagra here', 1),
                ('let us meet', 0),
                ('lunch tomorrow', 0),
            ]
            utils.reset_model()
            self.assertTrue(utils.predict_spam('Cheap viagra here'))
            self.assertFalse(utils.predict_spam('Lunch tomorrow'))


class CacheTests(TestCase):
    def test_cache_roundtrip(self):
        data = b'Test message'
        h, _ = utils.cache_lookup(data)
        utils.cache_store(h, {'result': 'ok'})
        _, cached = utils.cache_lookup(data)
        self.assertEqual(cached['result'], 'ok')