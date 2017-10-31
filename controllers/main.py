# -*- coding: utf-8 -*-
from odoo.addons.auth_oauth.controllers.main import OAuthLogin
import uuid
from odoo import http, _
import werkzeug.urls
from odoo.http import request
import functools
import urllib2


# helpers
def fragment_to_query_string(func):
    @functools.wraps(func)
    def wrapper(self, *a, **kw):
        kw.pop('debug', False)
        if not kw:
            return """<html><head><script>
                var l = window.location;
                var q = l.hash.substring(1);
                var r = l.pathname + l.search;
                if(q.length !== 0) {
                    var s = l.search ? (l.search === '?' ? '' : '&') : '?';
                    r = l.pathname + l.search + s + q;
                }
                if (r == l.pathname) {
                    r = '/';
                }
                window.location = r;
            </script></head><body></body></html>"""
        return func(self, *a, **kw)
    return wrapper


class Auth0OAuthLogin(OAuthLogin):
    def list_providers(self):
        # providers = super(Auth0OAuthLogin, self).list_providers()
        providers = request.env['auth.oauth.provider.auth0'].sudo().search_read([('enabled', '=', True)])

        if providers:
            for provider in providers:
                if provider['name'].lower() == 'auth0':
                    nonce = uuid.uuid4()
                    request.session['auth_oath_auth0.nonce'] = '%s' % nonce
                    params = dict(
                        scope=provider['scope'],
                        response_type='code',
                        client_id=provider['client_id'],
                        redirect_uri=request.httprequest.url_root + 'auth_oauth/auth0/callback',
                        state=nonce,
                    )
                    provider['auth_link'] = "%s?%s" % (provider['auth_endpoint'], werkzeug.url_encode(params))

                    print provider['auth_link']

        return providers

    @http.route('/auth_oauth/auth0/callback', type='http', auth='none')
    @fragment_to_query_string
    def signin(self, **kw):
        if request.params.get('state') != request.session['auth_oath_auth0']:
            return 'State check failed. Try again.'
        request.session['auth_oath_auth0.nonce'] = None
        request.session['auth_oath_auth0.access_token'] = request.params.get('access_token')
        providers = super(Auth0OAuthLogin, self).list_providers()
        for provider in providers:
            if provider['name'].lower() == 'auth0':
                data = urllib2.Request(
                    provider['validation_endpoint'],
                    None,
                    dict(Authorization='Bearer ' + request.session['auth_oath_auth0_token'])
                )
                print(data)
        return 'step 1. OK'
