# coding: utf8

import string  # pylint: disable-msg=deprecated-module
import json
import logging

from django.http import HttpResponseBadRequest, HttpResponse
from django.contrib.auth.models import User

from social.pipeline import partial

from student.views import create_account_with_params, reactivation_email_for_user
from student.models import UserProfile, CourseAccessRole
from student.roles import (
    CourseInstructorRole, CourseStaffRole, GlobalStaff, OrgStaffRole,
    UserBasedRole, CourseCreatorRole, CourseBetaTesterRole, OrgInstructorRole,
    LibraryUserRole, OrgLibraryUserRole
)
from third_party_auth.pipeline import (
    make_random_password, AuthEntryError
)
from opaque_keys.edx.keys import CourseKey

log = logging.getLogger(__name__)

# The following are various possible values for the AUTH_ENTRY_KEY.
AUTH_ENTRY_LOGIN = 'login'
AUTH_ENTRY_REGISTER = 'register'
AUTH_ENTRY_ACCOUNT_SETTINGS = 'account_settings'

AUTH_ENTRY_LOGIN_2 = 'account_login'
AUTH_ENTRY_REGISTER_2 = 'account_register'

# Entry modes into the authentication process by a remote API call (as opposed to a browser session).
AUTH_ENTRY_LOGIN_API = 'login_api'
AUTH_ENTRY_REGISTER_API = 'register_api'


def is_api(auth_entry):
    """Returns whether the auth entry point is via an API call."""
    return (auth_entry == AUTH_ENTRY_LOGIN_API) or (auth_entry == AUTH_ENTRY_REGISTER_API)


AUTH_DISPATCH_URLS = {
    AUTH_ENTRY_LOGIN: '/login',
    AUTH_ENTRY_REGISTER: '/register',
    AUTH_ENTRY_ACCOUNT_SETTINGS: '/account/settings',

    # This is left-over from an A/B test
    # of the new combined login/registration page (ECOM-369)
    # We need to keep both the old and new entry points
    # until every session from before the test ended has expired.
    AUTH_ENTRY_LOGIN_2: '/account/login/',
    AUTH_ENTRY_REGISTER_2: '/account/register/',

}

_AUTH_ENTRY_CHOICES = frozenset([
    AUTH_ENTRY_LOGIN,
    AUTH_ENTRY_REGISTER,
    AUTH_ENTRY_ACCOUNT_SETTINGS,

    AUTH_ENTRY_LOGIN_2,
    AUTH_ENTRY_REGISTER_2,

    AUTH_ENTRY_LOGIN_API,
    AUTH_ENTRY_REGISTER_API,
])

_DEFAULT_RANDOM_PASSWORD_LENGTH = 12
_PASSWORD_CHARSET = string.letters + string.digits

class JsonResponse(HttpResponse):
    def __init__(self, data=None):
        super(JsonResponse, self).__init__(
            json.dumps(data), mimetype='application/json; charset=utf-8'
        )


@partial.partial
def ensure_user_information(
    strategy, auth_entry, backend=None, user=None, social=None,
    allow_inactive_user=False, *args, **kwargs):
    """
    Ensure that we have the necessary information about a user (either an
    existing account or registration data) to proceed with the pipeline.
    """

    response = {}
    data = kwargs['response']

    def dispatch_to_register():
        """Force user creation on login or register"""

        request = strategy.request
        data['terms_of_service'] = True
        data['honor_code'] = True
        data['password'] = make_random_password()
        # force name creation if it is empty in sso-profile
        data['name'] = ' '.join([data.get('firstname', ''),
                                 data.get('lastname', '')]).strip() or data['username']
        data['provider'] = backend.name

        if request.session.get('ExternalAuthMap'):
            del request.session['ExternalAuthMap']

        try:
            user = User.objects.get(email=data['email'])
        except User.DoesNotExist:
            create_account_with_params(request, data)
            user = request.user
            user.is_active = True
            user.save()

        return {'user': user}

    if not user:
        if auth_entry in [AUTH_ENTRY_LOGIN_API, AUTH_ENTRY_REGISTER_API]:
            return HttpResponseBadRequest()
        elif auth_entry in [AUTH_ENTRY_LOGIN, AUTH_ENTRY_LOGIN_2]:
            response = dispatch_to_register()
        elif auth_entry in [AUTH_ENTRY_REGISTER, AUTH_ENTRY_REGISTER_2]:
            response = dispatch_to_register()
        elif auth_entry == AUTH_ENTRY_ACCOUNT_SETTINGS:
            raise AuthEntryError(
                backend, 'auth_entry is wrong. Settings requires a user.')
        else:
            raise AuthEntryError(backend, 'auth_entry invalid')
    else:
        if user.id != 1:
            user.email = data['email']
            user.username = data['username']
            user.save()

    user = user or response.get('user')
    if user and not user.is_active:
        if allow_inactive_user:
            pass
        elif social is not None:
            reactivation_email_for_user(user)
            log.warning(
                'User "%s" is using third_party_auth to login but has not yet activated their account. ',
                user.username
            )

    return response
