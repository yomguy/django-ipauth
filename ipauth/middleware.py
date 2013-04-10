# Much of this file is taken straight from django-ban project
import logging

from django.conf import settings

from ipauth.models import Range
from ipauth.signals import included_ip_found

import urlparse
from django.shortcuts import redirect

logger = logging.getLogger('django_ipauth: IP address filtering started')

splits = lambda x: x.replace(' ','').split(',')

def get_ip(req):
    ip = req.META['REMOTE_ADDR']
    # forwarded proxy fix for proxy passing setups
    if (not ip or ip == '127.0.0.1') and req.META.has_key('HTTP_X_FORWARDED_FOR'):
        ip = req.META['HTTP_X_FORWARDED_FOR']
    return ip

def is_ip_in_nets(ip, nets):
    for net in nets:
        if ip in net:
            return True
    return False

class AuthIPMiddleware(object):
    def process_request(self, request):
        # gather some info
        request_ip = get_ip(request)
        ip = IP(ip)
        ip_range = Range.objects.get(Q(lower=ip) | Q(lower__lte=ip, upper__gte=ip))

        if ip_range:
            print request_ip
            request.included_ip = True
            included_ip_found.send(sender=request, ip=request_ip)
            return redirect('ipauth.views.login')

