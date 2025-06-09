from django import forms

class UploadMsgForm(forms.Form):
    msg_file = forms.FileField(label='MSG file')
