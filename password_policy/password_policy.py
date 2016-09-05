# -*- encoding: utf-8 -*-
##############################################################################
#
#    open2bizz
#    Copyright (C) 2014 open2bizz (open2bizz.nl).
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
from openerp.osv import fields, osv 
from openerp import http, api, SUPERUSER_ID
from openerp.addons import web, auth_signup
from openerp.tools import DEFAULT_SERVER_DATETIME_FORMAT
from openerp.tools.translate import _
import openerp
from datetime import datetime, timedelta
import operator
from openerp.http import request
import logging
import random

from openerp.tools.translate import _
_logger = logging.getLogger(__name__)

class change_password_user_preferences(web.controllers.main.Session):
    @http.route('/web/session/change_password', type='json', auth="user")
    def change_password(self, fields):
        res = super(change_password_user_preferences,self).change_password(fields)
        password = res.get("new_password")
        if password is not None:
            pw_complex = request.registry.get('password.complexity').check_password_complexity(request.cr,request.uid, password, request.context)
            if not pw_complex[0]:
                raise osv.except_osv('Weak Password', pw_complex[1])
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
                    
                    pw_complex = request.registry.get('password.complexity').check_password_complexity(request.cr,request.uid, password, request.context)
                    if not pw_complex[0]:
                        qcontext['error'] = _(pw_complex[1])
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
                    user_schedule_model = request.registry.get("res.config.password_policy.sheduler")
                    user_schedule_id = user_schedule_model.search(request.cr,SUPERUSER_ID,[('user_id','=',user_id)])
                    if user_schedule_id:
                        user_schedule_obj = user_schedule_model.browse(request.cr,SUPERUSER_ID,user_schedule_id)
                        if user_schedule_obj.login_blocked:
                            values = request.params.copy()
                            values['error'] = _("Account has been blocked. Please change your password to regain access.")
                            return request.render('web.login', values)

        res = super(user_web_login, self).web_login(redirect, **kw)
        return res

    
class password_policy_user(osv.osv):
    _name = "res.users"
    _inherit = "res.users"
    
    def write(self,cr,uid,ids,vals,context=None):
        if not hasattr(ids, '__iter__'):
            ids = [ids]
        if vals.get('password'):
            if context:
                if context.get('ignore_pw_change'):
                    chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ!\"#$%&'()*+,-./:;<=>?@[\]^_`{|}~abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
                    vals.update({
                                 'password' : ''.join(random.SystemRandom().choice(chars) for x in range(vals.get('password')))
                                 })
            else:
                for id in ids:
                    self.pool.get('res.config.password_policy.sheduler').password_change_user(cr,id,context)
        res = super(password_policy_user, self).write(cr, uid,ids, vals, context=context)
        return res
    

    
class password_policy(osv.osv):
    _name = 'res.config.password_policy'
    _inherit = 'res.config.settings'
    
    _columns = {
                'minimum_password_length' : fields.integer("Minimum password length"),
                'check_upper_and_lower' : fields.boolean("Require upper- and lowercase characters"),
                'check_contains_number' : fields.boolean("Require use of number"),
                'check_only_numbers' : fields.boolean("Require not only numbers"),
                'minimum_special_characters' : fields.integer("Minimum special character amount"),
                'special_characters' : fields.char('Special Characters'),
                'check_names_in_password' : fields.boolean("Forbid names in password"),
                'password_expire_interval' : fields.integer("Days for a password to expire", help="0 = never expires"),
                'password_reset_duration' : fields.integer("Days the user has to (re)set his password before the token expires", help="0 = never expires"),
                'password_reminder_days' : fields.integer("Days for reminder before the password expires", help="0 = no reminder"),
                }
    
    def default_get(self, cr, uid, fields, context=None):
        return self.get_latest_configuration()
    
    def get_latest_configuration(self):
        res = {}
        cr = self.pool.cursor()
        ids = self.search(cr, SUPERUSER_ID,[])
        if ids:
            id = max(ids)
            obj = self.browse(cr,SUPERUSER_ID,id)[0]
            res['minimum_password_length'] = obj.minimum_password_length
            res['check_upper_and_lower'] = obj.check_upper_and_lower
            res['check_contains_number'] = obj.check_contains_number
            res['check_only_numbers'] = obj.check_only_numbers
            res['minimum_special_characters'] = obj.minimum_special_characters
            res['special_characters'] = obj.special_characters
            res['check_names_in_password'] = obj.check_names_in_password
            res['password_expire_interval'] = obj.password_expire_interval
            res['password_reset_duration'] = obj.password_reset_duration
            res['password_reminder_days'] = obj.password_reminder_days
        cr.close()          
        return res

    def get_password_expire_info(self):
        res = {}
        cr = self.pool.cursor()
        ids = self.search(cr, SUPERUSER_ID,[])
        if ids:
            id = max(ids)
            obj = self.browse(cr,SUPERUSER_ID,id)[0]
            res['password_expire_interval'] = obj.password_expire_interval
            res['password_reminder_days'] = obj.password_reminder_days
        cr.close()            
        return res
    
class password_policy(osv.osv):
    _name = 'password.complexity'
    
    def check_password_complexity(self,cr,uid, password,context=None):
        passed = True
      
        faultreasons = []
        res = []
        
        password_configuration = self.pool.get('res.config.password_policy').get_latest_configuration()
        if password_configuration:  
            if password_configuration['minimum_password_length'] > 0:
                checkresult = self.check_password_length(password, password_configuration['minimum_password_length'])
                if checkresult != True:
                    passed = False
                    faultreasons.append(checkresult)  
        
            if password_configuration['check_upper_and_lower']:
                checkresult = self.check_upper_and_lower(password)
                if checkresult != True:
                    passed = False
                    faultreasons.append(checkresult)
        
            if password_configuration['check_contains_number']:
                checkresult = self.check_contains_number(password)
                if checkresult != True:
                    passed = False
                    faultreasons.append(checkresult)
                
            if password_configuration['check_only_numbers']:
                checkresult = self.check_only_numbers(password)
                if checkresult != True:
                    passed = False
                    faultreasons.append(checkresult) 
                
            if password_configuration['minimum_special_characters'] > 0:
                special_characters = password_configuration['special_characters']
                checkresult = self.check_special_characters(password,password_configuration['minimum_special_characters'], special_characters)
                if checkresult != True:
                    passed = False
                    faultreasons.append(checkresult)   
                      
            if password_configuration['check_names_in_password']:
                checkresult = self.check_names_in_password(cr,uid, password, context)
                if checkresult != True:
                    passed = False
                    faultreasons.append(checkresult)
                
        if faultreasons:
            faultstring = ''
            for i in range(len(faultreasons)):
                faultstring += faultreasons[i]
                if i < len(faultreasons) - 1:
                    faultstring += "\n"    
            res = [passed, faultstring]
        else:
            res = [passed, ""]
        return res
     
    def check_upper_and_lower(self,password):
        if not (not password.islower() and not password.isupper() and not password.isdigit()):
            return "Password should contain upper and lower case characters"
        else:
            return True
     
    def check_contains_number(self,password):
        if not (any(char.isdigit() for char in password)):
            return "Password should contain at least one number"
        else:
            return True
     
    def check_special_characters(self,password,special_amount,special_characters):
        special_amount_found = 0
        for character in password:
            for special_character in special_characters:
                if character == special_character:
                    special_amount_found += 1
        if special_amount_found < special_amount:
            return "Password should contain at least %s of the following special characters: %s" % (special_amount,special_characters)
        else:
            return True
     
    def check_password_length(self, password, min_length):
        if len(password) < min_length:
            return "Password should be at least %s characters long" % min_length
        else:
            return True
     
    def check_names_in_password(self,cr,uid,password,context=None):
        user = self.pool.get("res.users").browse(cr,uid,uid,context)

        forbidden_words = []
        
        forbidden_words = user.name.lower().split(' ')
        login = user.login.lower().split('@')
        if len(login) > 1:
            domain = login[1].split('.')
            if len(domain) > 1:
                forbidden_words += [domain[0]]
        
        for ch in login[0].split('.'):
            if len(ch)>1:
                forbidden_words += [ch]

        forb_found = False
        for word in forbidden_words:
            if word in password.lower():
                forb_found = True

        if forb_found:
            _logger.error('Password entered that has at least 1 forbidden word in: %s' % forbidden_words)
            return "Password should not contain your login,username, firstname, suffix, lastname or domain name"
        else:
            return True
  
    def check_only_numbers(self, password):
        if password.isdigit():
            return "Password can not be just numbers"
        else:
            return True
    
class password_user(osv.osv):
    _name = 'res.partner'
    _inherit = 'res.partner'
    
    def now(self,**kwargs):
        dt = datetime.now() + timedelta(**kwargs)
        return dt.strftime(DEFAULT_SERVER_DATETIME_FORMAT)
    
    def set_expiration_date(self,cr,uid,ids):
        password_configuration = self.pool.get('res.config.password_policy').get_latest_configuration()
        if password_configuration['password_reset_duration'] != 0:
            return self.now(days=password_configuration['password_reset_duration'])
        elif password_configuration['password_reset_duration'] == 0:
            return False
        return self.now(days=1)
        
    def write(self, cr, uid, ids, data, *args, **argv):
        if data.get('signup_expiration'):
            data['signup_expiration'] = self.set_expiration_date(cr,uid,ids)
        res = super(password_user, self).write(cr, uid, ids, data, *args, **argv)
        return res

        


    
        
