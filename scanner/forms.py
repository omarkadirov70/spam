from django import forms
from django.core.validators import FileExtensionValidator

class UploadMsgForm(forms.Form):
    msg_file = forms.FileField(
        label='Email file (.msg or .eml)',
        validators=[FileExtensionValidator(['msg', 'eml'])],
    )
