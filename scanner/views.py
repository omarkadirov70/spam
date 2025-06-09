from django.shortcuts import render
from django.http import HttpRequest, HttpResponse
from .forms import UploadMsgForm
from . import utils
import extract_msg
from email import message_from_string


def upload(request: HttpRequest) -> HttpResponse:
    context = {'form': UploadMsgForm()}
    if request.method == 'POST':
        form = UploadMsgForm(request.POST, request.FILES)
        if form.is_valid():
            msg_file = form.cleaned_data['msg_file']
            message = extract_msg.Message(msg_file)
            body = message.body or ''
            header_obj = message.header
            headers = header_obj.as_string() if header_obj else ''
            email_msg = message_from_string(headers + "\n\n" + body)

            ips = set(utils.extract_ips(headers))
            domains = set(utils.extract_domains(body))
            ip_results = {ip: utils.query_dnsbl(ip) for ip in ips}
            domain_results = {d: utils.query_uribl(d) for d in domains}

            header_info = utils.parse_headers(email_msg)
            spf_result = None
            dkim_result = utils.check_dkim((headers + "\r\n\r\n" + body).encode())
            dmarc_result = None

            sender_domain = ''
            if header_info['from']:
                sender_domain = header_info['from'].split('@')[-1].strip('>')
            if ips and sender_domain:
                spf_result = utils.check_spf(next(iter(ips)), header_info['from'])
                dmarc_result = utils.check_dmarc(sender_domain)

            context.update({
                'ip_results': ip_results,
                'domain_results': domain_results,
                'header_info': header_info,
                'spf_result': spf_result,
                'dkim_result': dkim_result,
                'dmarc_result': dmarc_result,
                'form': form,
            })
    return render(request, 'scanner/upload.html', context)