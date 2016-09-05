# -*- encoding: utf-8 -*-
##############################################################################
#
#    open2bizz
#    Copyright (C) 2016 open2bizz (open2bizz.nl).
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU Affero General Public License as
#    published by the Free Software Foundation, either version 3 of the
#    License, or (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU Affero General Public License for more details.
#
#    You should have received a copy of the GNU Affero General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
##############################################################################
from openerp import http, SUPERUSER_ID
from openerp.http import request
from openerp.addons import web, auth_signup


class change_password_user_preferences(web.controllers.main.Session):
    @http.route('/web/session/change_password', type='json', auth="user")
    def change_password(self, fields):
        res = super(change_password_user_preferences,self).change_password(fields)
        password = res.get("new_password")
        if password is not None:
            pw_rules = request.registry.get('password.rules').check_password_rules(request.cr,request.uid, password, request.context)
            if not pw_rules[0]:
                raise except_orm(_('Weak Password', pw_rules[1]))
        return res
     
class change_password_user_reset(auth_signup.controllers.main.AuthSignupHome):
    @http.route('/web/reset_password', type='http', auth='public', website=True)
    def web_auth_reset_password(self, *args, **kw):
        qcontext = self.get_auth_signup_qcontext()
        password = None
        if qcontext.get('password') and qcontext.get('confirm_password'):
            if qcontext['password'] == qcontext['confirm_password']:
                password = qcontext['password']
        
        if 'error' not in qcontext and request.httprequest.method == 'POST':
            if qcontext.get('token'):
                if password:
                    
                    pw_rules = request.registry.get('password.rules').check_password_rules(request.cr,request.uid, password, request.context)
                    if not pw_rules[0]:
                        qcontext['error'] = _(pw_rules[1])
                        return request.render('auth_signup.reset_password', qcontext)
        res = super(change_password_user_reset, self).web_auth_reset_password(*args, **kw)
        return res
    
class user_web_login(web.controllers.main.Home):
    @http.route('/web/login', type='http', auth="none")
    def web_login(self, redirect=None, **kw):
        if request.httprequest.method == 'POST':
            user_model = request.registry.get("res.users")
            user_id = user_model.search(request.cr,SUPERUSER_ID,[('login','=',request.params['login'])])
            if user_id:
                if user_id != SUPERUSER_ID:
                    user_history_model = request.registry.get("password.rules.history")
                    user_history_id = user_history_model.search(request.cr,SUPERUSER_ID,[('user_id','=',user_id)])
                    if user_history_id:
                        user_history_obj = user_history_model.browse(request.cr,SUPERUSER_ID,user_history_id)
                        if user_history_obj.login_blocked:
                            values = request.params.copy()
                            values['error'] = _("Account has been blocked. Please change your password to regain access.")
                            return request.render('web.login', values)

        res = super(user_web_login, self).web_login(redirect, **kw)
        return res    