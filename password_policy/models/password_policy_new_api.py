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
from openerp import api, fields, models, SUPERUSER_ID
from openerp.addons.base.ir.ir_mail_server import MailDeliveryException
from openerp.tools import DEFAULT_SERVER_DATE_FORMAT
from openerp.tools.translate import _
import datetime
import random

import logging

_logger = logging.getLogger(__name__)

class PasswordPolicyUser(models.Model):
    _inherit = "res.users"
    
    password_never_expires = fields.Boolean("Password never expires")
    
    def write(self,cr,uid,ids,vals,context=None):
        _logger.error(vals)
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
                    self.pool.get('password.rules.history').password_change_user(cr,id,context)
        res = super(PasswordPolicyUser, self).write(cr, uid,ids, vals, context=context)
        return res
    
class PasswordPartner(models.Model):
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
        res = super(PasswordPartner, self).write(cr, uid, ids, data, *args, **argv)
        return res


    
    
    
    
    
    




