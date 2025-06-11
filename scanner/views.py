from django.shortcuts import render
from django.http import HttpRequest, HttpResponse
from .forms import UploadMsgForm
from . import utils
import extract_msg
from email import message_from_bytes, message_from_string


def stats(request: HttpRequest) -> HttpResponse:
    data = utils.scan_statistics()
    return render(request, 'scanner/stats.html', data)


def upload(request: HttpRequest) -> HttpResponse:
    context = {'form': UploadMsgForm()}
    if request.method == 'POST':
        form = UploadMsgForm(request.POST, request.FILES)
        if form.is_valid():
            msg_file = form.cleaned_data['msg_file']
            name = msg_file.name.lower()
            if name.endswith('.msg'):
                message = extract_msg.Message(msg_file)
                body = message.body or ''
                header_obj = message.header
                headers = header_obj.as_string() if header_obj else ''
                msg_bytes = (headers + "\n\n" + body).encode()
                email_msg = message_from_string(headers + "\n\n" + body)
            else:
                data = msg_file.read()
                message = message_from_bytes(data)
                if message.is_multipart():
                    parts = []
                    for part in message.walk():
                        if part.is_multipart():
                            continue
                        if part.get_content_type().startswith('text/'):
                            payload = part.get_payload(decode=True) or b''
                            charset = part.get_content_charset() or 'utf-8'
                            try:
                                parts.append(payload.decode(charset, errors='ignore'))
                            except Exception:
                                parts.append(payload.decode('utf-8', errors='ignore'))
                    body = "\n".join(parts)
                else:
                    payload = message.get_payload(decode=True) or b''
                    charset = message.get_content_charset() or 'utf-8'
                    try:
                        body = payload.decode(charset, errors='ignore')
                    except Exception:
                        body = payload.decode('utf-8', errors='ignore')
                headers = ''.join(f'{k}: {v}\n' for k, v in message.items())
                msg_bytes = data
                email_msg = message

            hash_val, cached = utils.cache_lookup(msg_bytes)
            if cached:
                context.update(cached)
                context['cached'] = True
            else:
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

                keyword_hits = utils.find_keywords(body)
                word_freqs = utils.word_frequencies(body)
                links = utils.extract_urls(body)
                suspicious_atts = utils.suspicious_attachments(message)
                ml_spam = utils.predict_spam(body)

                result = {
                    'ip_results': ip_results,
                    'domain_results': domain_results,
                    'header_info': header_info,
                    'spf_result': spf_result,
                    'dkim_result': dkim_result,
                    'dmarc_result': dmarc_result,
                    'keyword_hits': keyword_hits,
                    'word_freqs': word_freqs,
                    'links': links,
                    'suspicious_attachments': suspicious_atts,
                    'ml_spam': ml_spam,
                }
                score = utils.compute_score(result)
                result['spam_score'] = round(score, 2)
                result['overall_spam'] = utils.is_spam_score(score)
                utils.cache_store(hash_val, result)
                utils.log_result(hash_val, result)
                context.update(result)
                context['cached'] = False

            context['form'] = form
    return render(request, 'scanner/upload.html', context)