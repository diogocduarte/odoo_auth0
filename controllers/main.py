# -*- coding: utf-8 -*-
from odoo.addons.auth_oauth.controllers.main import OAuthLogin
import uuid
from odoo import http, _
import werkzeug
import werkzeug.urls
from odoo.http import request
import json
import urllib2
import logging
import jwt
import random
from passlib.context import CryptContext
from odoo.addons.web.controllers.main import set_cookie_and_redirect

_logger = logging.getLogger(__name__)


class Auth0OAuthLogin(OAuthLogin):
    def list_providers(self):
        # providers = super(Auth0OAuthLogin, self).list_providers()
        providers = request.env['auth.oauth.provider'].sudo().search_read([
            ('enabled', '=', True),
            ('client_secret', '!=', ''),
        ])

        if providers:
            for provider in providers:
                if '.auth0.com/authorize' in provider['auth_endpoint'].lower():
                    nonce = uuid.uuid4()
                    request.session['auth0.nonce'] = '%s|%d' % (nonce, provider['id'])
                    request.session['auth0.session_db'] = request.session.db
                    scope = provider['scope'] if 'email' in provider['scope'] else provider['scope'] + ' email'
                    params = dict(
                        scope=scope,
                        response_type='code',
                        client_id=provider['client_id'],
                        redirect_uri=request.httprequest.url_root + 'auth0/callback',
                        state=request.session['auth0.nonce'],
                    )
                    provider['auth_link'] = "%s?%s" % (provider['auth_endpoint'], werkzeug.url_encode(params))

        return providers

    @http.route('/auth0/callback', type='http', auth='none')
    def signin(self, **kw):
        # todo: instead of showing an error, generate new session data and redirect to Auth0
        if not request.session['auth0.nonce']:
            return werkzeug.utils.redirect('/web/login?err=Auth session expired - Try again', code=302)
        if request.params.get('state').replace('%7', '|') != request.session['auth0.nonce']:
            request.session['auth0.nonce'] = None
            return 'State check failed (1). Try again.'
        provider_id = request.session['auth0.nonce'].split('|')[1]
        if not request.params.get('code'):
            return 'Expected "code" param in URL, but its not there. Try again.'
        request.session['auth0.nonce'] = None
        code = request.params.get('code')
        profile = self._validate(code, provider_id)

        # todo: create pages with explanations and make it easier for the user to retry
        if not profile:
            return 'Profile validation failed. Try again.'
        if not profile['email_verified']:
            return 'Please verify your email first then try again.'

        # sure the user is authentic, but do they have a login for this DB?
        login = profile['email']
        password = self._ensure_password(login)
        if not password:
            return 'You are not allowed access to this database (1)'
        login_uid = request.session.authenticate(request.session['auth0.session_db'], login, password)
        if login_uid is False:
            return 'You are not allowed access to this database (2)'

        return set_cookie_and_redirect('/web')

    def _validate(self, authorization_code, provider_id):
        # lookup the secret for the provider
        provider = request.env['auth.oauth.provider'].sudo().search_read([('id', '=', provider_id)])
        if not len(provider):
            return False
        provider = provider[0]
        # config may have changed during login process so we make sure we still have values we need
        if not provider['client_id'] or not provider['client_secret'] or not provider['validation_endpoint']:
            return False
        # exchange the authorization code for an access token
        post_data = json.dumps(dict(
            grant_type='authorization_code',
            code=authorization_code,
            client_id=provider['client_id'],
            client_secret=provider['client_secret'],
            redirect_uri=request.httprequest.url_root + 'auth0/callback',
        ))
        req = urllib2.Request(provider['validation_endpoint'], post_data)
        req.add_header('Content-Type', 'application/json')
        try:
            resp = urllib2.urlopen(req)
            mime_type = resp.info().getheader('Content-Type')
            if mime_type != 'application/json' or resp.code != 200:
                _logger.error('API call made to %s did not return the expected response' % provider['validation_endpoint'])
                return False
        except urllib2.HTTPError as e:
            _logger.error('%s API request failed: status code=%s; reason=%s'
                          % (provider['validation_endpoint'], e.code, e.reason))
            return False

        # keep an eye on rate limits
        self._check_rate_limits(resp)

        try:
            data = resp.read()
            data = json.loads(data)
        except Exception, e:
            _logger.error('failed decoding JSON response from %s: %s'
                          % (provider['validation_endpoint'], json.dumps(e)))
            return False

        # Access tokens are deprecated - don't store it - see https://auth0.com/docs/api/management/v1
        # removed code: request.session['auth0.access_token'] = data['access_token']
        # Save the JWT which is returned as the "id_token"
        request.session['auth0.id_token'] = data['id_token']
        request.session['auth0.provider_id'] = provider_id
        profile = self.get_profile_data(request, provider['jwt_secret'])
        return profile

    def _check_rate_limits(self, validation_response):
        rate_limit_remaining = validation_response.headers.get('X-RateLimit-Remaining')
        if rate_limit_remaining.isdigit():
            rate_limit_remaining = int(rate_limit_remaining)
            if rate_limit_remaining < 2000:
                _logger.warn('Auth0 rate limit remaining: %d' % rate_limit_remaining)
            elif rate_limit_remaining < 500:
                _logger.warn('[critical] Auth0 rate limit remaining: %d' % rate_limit_remaining)

    @staticmethod
    def get_profile_data(request_obj, jwt_secret=None):
        if not request_obj.session['auth0.provider_id'].isdigit() or not request_obj.session['auth0.id_token']:
            return False

        # lookup the secret if it was not provided ~ it could still be none if it was not configured in settings
        if jwt_secret is None:
            provider = request_obj.env['auth.oauth.provider'].sudo().search_read([('id', '=', request_obj.session['auth0.provider_id'])])
            if not len(provider):
                return False
            provider = provider[0]
            jwt_secret = provider['jwt_secret'] if provider['jwt_secret'] else None

        if not jwt_secret:
            data = jwt.decode(request_obj.session['auth0.id_token'], verify=False)
        else:
            data = jwt.decode(request_obj.session['auth0.id_token'], key=jwt_secret)
        return data

    def _ensure_password(self, login):
        # get the id as variant value for the encrypted password
        # this way we also ensure the user's login even exists
        login = request.env['res.users'].sudo().search_read([('login', '=', login)])
        if not len(login):
            return False
        login = login[0]

        # generate a temporary hashed password and set it in the database
        tmp_password = '%032x' % random.getrandbits(128)
        # paradigm from odoo.addons.auth_crypt.models.res_users
        encrypted = CryptContext(['pbkdf2_sha512']).encrypt(tmp_password)
        request.env.cr.execute(
            "UPDATE res_users SET  password='', password_crypt=%s WHERE id=%s",
            (encrypted, login['id']))
        request.env.cr.commit()
        # we can now login with this temporary password
        return tmp_password
