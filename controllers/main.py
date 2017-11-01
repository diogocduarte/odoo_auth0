# -*- coding: utf-8 -*-
from odoo.addons.auth_oauth.controllers.main import OAuthLogin
import uuid
from odoo import http, _
import werkzeug.urls
from odoo.http import request
import json
import urllib2
import logging
import jwt

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
                    params = dict(
                        scope=provider['scope'],
                        response_type='code',
                        client_id=provider['client_id'],
                        redirect_uri=request.httprequest.url_root + 'auth0/callback',
                        state=request.session['auth0.nonce'],
                    )
                    provider['auth_link'] = "%s?%s" % (provider['auth_endpoint'], werkzeug.url_encode(params))

                    print provider['auth_link']

        return providers

    @http.route('/auth0/callback', type='http', auth='none')
    def signin(self, **kw):
        if not request.session['auth0.nonce']:
            request.redirect('/web/login')
            return
        if request.params.get('state').replace('%7', '|') != request.session['auth0.nonce']:
            request.session['auth0.nonce'] = None
            return 'State check failed (1). Try again.'
        provider_id = request.session['auth0.nonce'].split('|')[1]
        if not request.params.get('code'):
            return 'Expected "code" param in URL, but its not there. Try again.'
        request.session['auth0.nonce'] = None
        code = request.params.get('code')
        profile = self._validate(code, provider_id)
        if not profile:
            return 'Profile validation failed. Try again.'
        return profile

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
                _logger.error('API call made to %s did not return the expected response' % provider['auth_url'])
                return False
        except urllib2.HTTPError as e:
            _logger.error('%s API request failed: status code=%s; reason=%s'
                          % (provider['auth_url'], e.code, e.reason))
            return False
        data = resp.read()
        data = json.loads(data)
        # todo: encrypt the access_tokens before saving it to the session (?)
        request.session['auth0.access_token'] = data['access_token']
        request.session['auth0.id_token'] = data['id_token']
        return self._get_profile(data['id_token'], provider['client_secret'])

    def _get_profile(self, id_token, secret):
        if not request.session['auth0.id_token']:
            return False
        data = jwt.decode(id_token, secret)
        return data
