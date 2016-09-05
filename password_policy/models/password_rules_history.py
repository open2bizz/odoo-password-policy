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
from openerp.tools import DEFAULT_SERVER_DATETIME_FORMAT
from openerp.tools.translate import _
from openerp.exceptions import except_orm
from datetime import datetime, timedelta
import logging
_logger = logging.getLogger(__name__)



class PasswordPolicyHistory(models.Model):
    _name = "password.rules.history"
    _description = "History for users password changing"

    user_id = fields.Many2one(
            'res.users',
            'User',
            readonly=True
            )
    last_password_change = fields.Date(
            "Last password change",
            readonly=True
            )
    login_blocked = fields.Boolean(
            "Login Blocked",
            readonly=True
            )
    reminder_send = fields.Boolean(
            "Reminder send for password change"
            ,readonly=True
            )
    password_expiry_date = fields.Date(
            "Password Expiry Date",
            compute="_get_expiry_and_reminder_date",
            readonly=True
            )
    password_reminder_ids = fields.One2many(
            'password.rules.history.reminder',
            'password_history_id',
            string='Password Reminders'
            ) 
    fields.Date("Password Change Reminder Date", compute="_get_expiry_and_reminder_date" ,readonly=True)
    
    @api.one
    def _get_expiry_and_reminder_date(self):
        self.password_expiry_date = False
        self.password_reminder_date = False
        config = self.pool.get('res.config.password_policy').get_password_expire_info()
        expire_interval = config.get('password_expire_interval')
        reminder_days = config.get('password_reminder_days')
        if self.last_password_change:
            if expire_interval > 0:
                last_change = datetime.datetime.strptime(self.last_password_change, DEFAULT_SERVER_DATE_FORMAT)
                self.password_expiry_date = last_change + datetime.timedelta(days=expire_interval)
        
        if self.password_expiry_date:
            if reminder_days > 0:
                expiry_date = datetime.datetime.strptime(self.password_expiry_date , DEFAULT_SERVER_DATE_FORMAT)
                self.password_reminder_date = expiry_date - datetime.timedelta(days=reminder_days)

    
class PasswordPolicyHistory(models.Model):
    _name = "password.rules.history.reminder"
    
    date = fields.Date(
            "Date to send reminder"
            )
    send = fields.Boolean(
            'Reminder Send'
            )
    password_history_id = fields.Many2one(
            "password.rules.history"
            )
    user_id = fields.Many2one(
            'res.users',
            'User',
            related="password_history_id.user_id"
            )

class UserPasswords(models.Model):
    _name = "password.rules.history.password"
    
    date = fields.Date(
            "Password Change Date"
            )
    password = fields.Char(
            "Password"
            )
    password_history_id = fields.Many2one(
            "password.rules.history"
            )
    user_id = fields.Many2one(
            "User",
            related="password_history_id.user_id"
            )
    
