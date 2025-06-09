from django.test import TestCase, Client
from django.urls import reverse
import email
from . import utils


class UploadViewTests(TestCase):
    def test_upload_page_loads(self):
        client = Client()
        response = client.get(reverse('upload'))
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