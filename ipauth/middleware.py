# Much of this file is taken straight from django-ban project
import logging

from django.db.models import Q
from django.shortcuts import redirect

from ipauth.models import Range, IP
from ipauth.signals import included_ip_found
import urlparse

from django.conf import settings
from django.contrib.auth import REDIRECT_FIELD_NAME, authenticate, login as auth_login
from django.contrib.auth.views import login as base_login_view
from django.contrib import messages
from django.http import HttpResponseRedirect
from django.views.decorators.cache import never_cache
from django.views.decorators.csrf import csrf_protect


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
    
    def process_request(self, request, redirect_field_name=REDIRECT_FIELD_NAME):
        # gather some info
        user = request.user
        request_ip = get_ip(request)
        ip = IP(request_ip)
        ip_range = Range.objects.get(Q(lower=ip) | Q(lower__lte=ip, upper__gte=ip))
        redirect_to = request.REQUEST.get(redirect_field_name, '')

        if ip_range and not user.is_authenticated():
            request.included_ip = True
            included_ip_found.send(sender=request, ip=request_ip)

            user = authenticate(ip=request_ip)

            if user is None:
                return base_login_view(request, redirect_field_name=redirect_field_name,
                                       **kwargs)

            auth_login(request, user)

            messages.add_message(request, messages.INFO,
                                'You are now logged in as %s' % (user.get_full_name(),))

            netloc = urlparse.urlparse(redirect_to)[1]

            # Use default setting if redirect_to is empty
            if not redirect_to:
                redirect_to = settings.LOGIN_REDIRECT_URL

            # Security check -- don't allow redirection to a different
            # host.
            elif netloc and netloc != request.get_host():
                redirect_to = settings.LOGIN_REDIRECT_URL

            if request.session.test_cookie_worked():
                request.session.delete_test_cookie()

            return HttpResponseRedirect(redirect_to)


