# -*- coding: utf-8 -*-
import json

import requests
from odoo import api, models, fields
from odoo.addons.auth_signup.models.res_users import SignupError
from odoo.exceptions import AccessDenied


class ResUsers(models.Model):
    _inherit = 'res.users'

    oauth_uuid = fields.Char(string='OAuth UUID', copy=False)

    @api.model
    def _generate_signup_values(self, provider, validation, params):
        oauth_uid = validation['user_id']
        oauth_uuid = False if 'uuid' not in validation else validation['uuid']
        email = validation.get('email', 'provider_%s_user_%s' % (provider, oauth_uid))
        name = validation.get('name', email)
        return {
            'name': name,
            'login': email,
            'email': email,
            'oauth_provider_id': provider,
            'oauth_uid': oauth_uid,
            'oauth_uuid': oauth_uuid,
            'oauth_access_token': params['access_token'],
            'active': True,
        }

    @api.model
    def _auth_oauth_signin(self, provider, validation, params):
        """ retrieve and sign in the user corresponding to provider and validated access token
            :param provider: oauth provider id (int)
            :param validation: result of validation of access token (dict)
            :param params: oauth parameters (dict)
            :return: user login (str)
            :raise: AccessDenied if signin failed

            This method can be overridden to add alternative signin methods.
        """
        oauth_uid = validation['user_id']
        try:
            oauth_user = self.search([("oauth_uid", "=", oauth_uid), ('oauth_provider_id', '=', provider)])
            if not oauth_user:
                raise AccessDenied()
            assert len(oauth_user) == 1

            validation = self.request_oauth_user_info(params['access_token'])
            if not validation:
                raise AccessDenied()

            self.update_oauth_user_info(oauth_user, provider, validation, params)

            return oauth_user.login
        except AccessDenied, access_denied_exception:
            if self.env.context.get('no_user_creation'):
                return None
            state = json.loads(params['state'])
            token = state.get('t')
            values = self._generate_signup_values(provider, validation, params)
            try:
                _, login, _ = self.signup(values, token)
                return login
            except SignupError:
                raise access_denied_exception

    @api.model
    def auth_oauth(self, provider, params):
        # Advice by Google (to avoid Confused Deputy Problem)
        # if validation.audience != OUR_CLIENT_ID:
        #   abort()
        # else:
        #   continue with the process
        access_token = params.get('access_token')
        code = params.get('code')
        validation = self._auth_oauth_validate(provider, access_token, code)

        params['access_token'] = validation['access_token']
        access_token = validation['access_token']

        # required check
        if not validation.get('user_id'):
            # Workaround: facebook does not send 'user_id' in Open Graph Api
            if validation.get('id'):
                validation['user_id'] = validation['id']
            else:
                validation = self.request_oauth_user_info(access_token)
                if not validation:
                    raise AccessDenied()

        # retrieve and sign in user
        login = self._auth_oauth_signin(provider, validation, params)
        if not login:
            raise AccessDenied()
        # return user credentials

        return (self.env.cr.dbname, login, access_token)

    @api.model
    def _auth_oauth_validate(self, provider, access_token, code):
        """ return the validation data corresponding to the access token """
        oauth_provider = self.env['auth.oauth.provider'].browse(provider)
        validation = self._auth_oauth_rpc(oauth_provider.validation_endpoint, access_token, code, provider)
        if validation.get('error'):
            raise Exception(validation['error'])
        if oauth_provider.data_endpoint:
            data = self._auth_oauth_rpc(oauth_provider.data_endpoint, access_token, code, provider)
            validation.update(data)
        return validation

    @api.model
    def _auth_oauth_rpc(self, endpoint, access_token, code, provider_id):
        url = endpoint

        providers = self.env['auth.oauth.provider'].sudo().search([('id', '=', provider_id)], limit=1)

        f = requests.post(url, params={
            'grant_type': 'authorization_code',
            'client_id': providers[0].client_id,
            'client_secret': providers[0].client_secret,
            'redirect_uri': '%s/auth_oauth/signin' % (self.env['ir.config_parameter'].get_param('web.base.url')),
            'code': code,
        })
        response = f.content
        return json.loads(response)

    def request_oauth_user_info(self, access_token):
        try:
            url = self.env['ir.config_parameter'].get_param('auth0_oauth.url_api_users')
            headers = {'Authorization': 'Bearer %s' % access_token}

            f = requests.get(url=url, headers=headers)
            response = f.content
            response = json.loads(response)

            if not response.get('error'):
                return {
                    'user_id': response['id'],
                    'uuid': response['uuid'],
                    'name': '%s %s' % (response['first_name'], response['last_name']),
                    'email': response['email'],
                }
        except:
            pass
        return False

    def update_oauth_user_info(self, oauth_user, provider, validation, params):
        oauth_uid = validation['user_id']
        oauth_uuid = False if 'uuid' not in validation else validation['uuid']
        email = validation.get('email', 'provider_%s_user_%s' % (provider, oauth_uid))
        name = validation.get('name', email)
        oauth_user.sudo().write({
            'name': name,
            'login': email,
            'email': email,
            'oauth_provider_id': provider,
            'oauth_uid': oauth_uid,
            'oauth_uuid': oauth_uuid,
            'oauth_access_token': params['access_token'],
            'active': True,
        })
