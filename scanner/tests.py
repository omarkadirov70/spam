from django.test import TestCase, Client
from django.urls import reverse


class UploadViewTests(TestCase):
    def test_upload_page_loads(self):
        client = Client()
        response = client.get(reverse('upload'))
        self.assertEqual(response.status_code, 200)
