# coding: utf8

import re
import os.path
import requests

from django.conf import settings
from django.core.urlresolvers import reverse
from django.contrib.auth import REDIRECT_FIELD_NAME, logout
from django.shortcuts import redirect

from social.apps.django_app.views import auth, NAMESPACE
from .views import logout as sso_logout
try:
    from opaque_keys.edx.keys import CourseKey
except:
    msg = "Oh, it's not edx"
    pass


class SeamlessAuthorization(object):
    cookie_name = 'authenticated'

    def process_request(self, request):
        """
        Check multidomain cookie and if user is authenticated on sso, login it on edx
        """
        backend = settings.SSO_NPOED_BACKEND_NAME
        current_url = request.get_full_path()

        # Special URLs (SSO-299)
        if '/handler_noauth/' in current_url:
            return None

        # Special URLs (EDX-310)
        if '/xqueue/' in current_url:
            return None

        # ITMO url hardcode
        special_xblock_url = 'courses/course-v1:ITMOUniversity+WEBDEV+fall_2015/xblock/block-v1:ITMOUniversity+WEBDEV+fall_2015+type'
        if special_xblock_url in current_url:
            return None

        special_xblock_url = 'courses/course-v1:ITMOUniversity+WEBDEV+spring_2016/xblock/block-v1:ITMOUniversity+WEBDEV+spring_2016+type'
        if special_xblock_url in current_url:
            return None

        # ITMO url hardcode 2
        course_id_itmo = 'courses/course-v1:ITMOUniversity+'
        handler_itmo_academy = '/handler/check_lab'
        if course_id_itmo in current_url and handler_itmo_academy in current_url:
            return None

        # UrFU url hardcode
        special_urfu_xblock_url = 'courses/course-v1:urfu+METR+fall_2015/xblock/block-v1:urfu+METR+fall_2015+type'
        if special_urfu_xblock_url in current_url:
            return None

        if 'certificates' in current_url:
            return None

        # don't work for admin
        in_exclude_path = False
        for attr in ['SOCIAL_AUTH_EXCLUDE_URL_PATTERN', 'AUTOCOMPLETE_EXCLUDE_URL_PATTERN']:
            if hasattr(settings, attr):
                r = re.compile(getattr(settings, attr))
                if r.match(current_url):
                    in_exclude_path = True
                    break

        auth_cookie = request.COOKIES.get(self.cookie_name, '0').lower()
        auth_cookie_user = request.COOKIES.get('{}_user'.format(self.cookie_name))
        auth_cookie = (auth_cookie in ('1', 'true', 'ok'))
        continue_url = reverse('{0}:complete'.format(NAMESPACE),
                               args=(backend,))
        is_auth = request.user.is_authenticated()
        # TODO: Need to uncomment after fix PLP
        is_same_user = (request.user.username == auth_cookie_user)

        # Check for infinity redirection loop
        is_continue = (continue_url in current_url)

        if (auth_cookie and not is_continue and (not is_auth or not is_same_user)) or \
                ('force_auth' in request.session and request.session.pop('force_auth')):
            query_dict = request.GET.copy()
            query_dict[REDIRECT_FIELD_NAME] = current_url
            query_dict['auth_entry'] = 'login'
            request.GET = query_dict
            logout(request)
            return auth(request, backend)
        elif not auth_cookie and is_auth and not in_exclude_path:
            # Logout if user isn't logined on sso except for admin
            logout(request)

        if request.user.is_authenticated() and not request.user.is_active:
            return sso_logout(request)

        return None
