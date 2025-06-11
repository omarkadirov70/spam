from django import forms
from django.core.validators import FileExtensionValidator


class MultiFileInput(forms.ClearableFileInput):
    allow_multiple_selected = True

class UploadMsgForm(forms.Form):
    msg_file = forms.FileField(
        label='Email file(s)',
        widget=MultiFileInput(attrs={'multiple': True}),
        validators=[FileExtensionValidator(['msg', 'eml'])],
    )