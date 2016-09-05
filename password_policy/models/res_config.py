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
from openerp import api, fields, models, SUPERUSER_ID
from openerp.tools.translate import _
import logging
_logger = logging.getLogger(__name__)

class PasswordPolicyConfig(models.Model):
    _name = 'res.config.password_policy'
    _inherit = 'res.config.settings'
    
    minimum_password_length = fields.Integer(
            "Minimum password length"
            )
    check_upper_and_lower = fields.Boolean(
            "Require upper- and lowercase characters"
            )
    check_contains_number = fields.Boolean(
            "Require use of number"
            )
    check_only_numbers = fields.Boolean(
            "Require not only numbers"
            )
    minimum_special_characters = fields.Integer(
            "Minimum special character amount"
            )
    special_characters = fields.Char(
            'Special Characters'
            )
    check_names_in_password = fields.Boolean(
            "Forbid names in password"
            )
    password_expire_interval = fields.Integer(
            "Days for a password to expire",
            help="0 = never expires")
    password_reset_duration = fields.Integer(
            "Days the user has to (re)set his password before the token expires",
            help="0 = never expires"
            )
    password_reminder_day_ids = fields.One2many(
            'res.config.password_policy.reminder',
            'config_id',
            string="Reminder Days"
            )
    password_rejection_amount = fields.Integer(
            "Amount of previous passwords to reject to get as new password",
            help="0 = all new passwords can be used"
            )
                
    
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
            res['password_reminder_day_ids'] = obj.password_reminder_day_ids.ids
            res['password_rejection_amount'] = obj.password_rejection_amount
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
            res['password_reminder_day_ids'] = obj.password_reminder_day_ids.ids
        cr.close()            
        return res
    
class PasswordPolicyConfigReminder(models.Model):
    _name = 'res.config.password_policy.reminder'
    
    config_id = fields.Many2one(
            'res.config.password_policy',
            'Config'            
            )
    password_reminder_day = fields.Integer(
            "Days for reminder before the password expires",
            help="0 = no reminder")
    
    @api.one
    @api.constrains('password_reminder_day')
    def _check_description(self):
        _logger.error(self.search([('id', '!=', self.id), ('password_reminder_day', '=', self.password_reminder_day)]))
        if self.search([('id', '!=', self.id), ('password_reminder_day', '=', self.password_reminder_day)]):
            raise ValueError(_("Reminder day value already excists"))
