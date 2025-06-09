from django.shortcuts import render
from django.http import HttpRequest, HttpResponse
from .forms import UploadMsgForm
from . import utils
import extract_msg


def upload(request: HttpRequest) -> HttpResponse:
    context = {'form': UploadMsgForm()}
    if request.method == 'POST':
        form = UploadMsgForm(request.POST, request.FILES)
        if form.is_valid():
            msg_file = form.cleaned_data['msg_file']
            message = extract_msg.Message(msg_file)
            body = message.body or ''
            headers = message.header or ''
            ips = set(utils.extract_ips(headers))
            domains = set(utils.extract_domains(body))
            ip_results = {ip: utils.query_dnsbl(ip) for ip in ips}
            domain_results = {d: utils.query_uribl(d) for d in domains}
            context.update({
                'ip_results': ip_results,
                'domain_results': domain_results,
                'form': form,
            })
    return render(request, 'scanner/upload.html', context)
