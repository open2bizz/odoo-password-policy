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
from openerp.osv import osv
from openerp import fields, SUPERUSER_ID,api
from openerp.addons.base.ir.ir_mail_server import MailDeliveryException
from openerp.tools import DEFAULT_SERVER_DATE_FORMAT
from openerp.tools.translate import _
import datetime


import logging

_logger = logging.getLogger(__name__)

class password_policy_user(osv.osv):
    _name = "res.users"
    _inherit = "res.users"
    
    password_never_expires = fields.Boolean("Password never expires")
    
class password_policy_sheduler(osv.osv):
    _name = "res.config.password_policy.sheduler"
    _description = "Scheduling for users password changing"

    user_id = fields.Many2one('res.users','User' ,readonly=True)
    last_password_change = fields.Date("Last password change" ,readonly=True)
    login_blocked = fields.Boolean("Login Blocked" ,readonly=True)
    reminder_send = fields.Boolean("Reminder send for password change" ,readonly=True)
    password_expiry_date = fields.Date("Password Expiry Date", compute="_get_expiry_and_reminder_date" ,readonly=True)
    password_reminder_date = fields.Date("Password Change Reminder Date", compute="_get_expiry_and_reminder_date" ,readonly=True)
    
    def get_ignore_ids(self,cr,uid,context=None):
        user_model = self.pool.get("res.users")
        user_filter = [("password_never_expires" , '=' , True)]
        user_ids = user_model.search(cr,SUPERUSER_ID,user_filter,context)
        if SUPERUSER_ID not in user_ids:
            user_ids.append(SUPERUSER_ID)
        return user_ids
    
    def password_change_user(self,cr,uid,context=None):
        if uid not in self.get_ignore_ids(cr, uid, context):
            exists = self.search(cr,SUPERUSER_ID,[('user_id','=',uid)])
            schedule_data = {
                            'last_password_change' : datetime.datetime.now().date(),
                            'login_blocked' : False,
                            'reminder_send' : False
                                }            
            if exists:
                self.write(cr,SUPERUSER_ID,exists,schedule_data)
            
            else:
                schedule_data.update({   
                                     'user_id' : uid,
                                })
                self.create(cr,SUPERUSER_ID,schedule_data,context)

    @api.one
    def _get_expiry_and_reminder_date(self):
        self.password_expiry_date = False
        self.password_reminder_date = False
        password_policy = self.pool.get('res.config.password_policy').get_password_expire_info()
        expire_interval = password_policy.get('password_expire_interval')
        reminder_days = password_policy.get('password_reminder_days')
        if self.last_password_change:
            if expire_interval > 0:
                last_change = datetime.datetime.strptime(self.last_password_change, DEFAULT_SERVER_DATE_FORMAT)
                self.password_expiry_date = last_change + datetime.timedelta(days=expire_interval)
        
        if self.password_expiry_date:
            if reminder_days > 0:
                expiry_date = datetime.datetime.strptime(self.password_expiry_date , DEFAULT_SERVER_DATE_FORMAT)
                self.password_reminder_date = expiry_date - datetime.timedelta(days=reminder_days)
    
    
    def run_password_scheduler(self, cr, uid):
        password_policy = self.pool.get('res.config.password_policy').get_password_expire_info()
        send_mail_possible = True
        if password_policy.get('password_expire_interval') > 0:
            self.check_users_in_passwordchange()
            ids = self.search(cr,SUPERUSER_ID, [])
            for user in self.browse(cr,SUPERUSER_ID, ids):
                if user.user_id.id != SUPERUSER_ID and not user.login_blocked:
                    current_date = datetime.datetime.combine(datetime.datetime.now().date(), datetime.time(0))
                    
                    if user.password_expiry_date:
                        expire_date = datetime.datetime.strptime(user.password_expiry_date, DEFAULT_SERVER_DATE_FORMAT)
                        if current_date >= expire_date:
                            self.block_login(user.id , user.user_id.id,send_mail_possible)
                    
                    if user.password_reminder_date:    
                        reminder_date = datetime.datetime.strptime(user.password_reminder_date, DEFAULT_SERVER_DATE_FORMAT)
                        if  current_date >= reminder_date and current_date < expire_date and user.reminder_send == False:
                             if send_mail_possible:
                                 send_mail_possible = self.send_reminder(user.id , user.user_id.id,send_mail_possible)

    def check_users_in_passwordchange(self):
        context = {}
        cr = self.pool.cursor()
        user_model = self.pool.get("res.users")
        user_ids = user_model.search(cr,SUPERUSER_ID,[('active','=',True),('id','not in', self.get_ignore_ids(cr, SUPERUSER_ID, context))])
        #removes the scheduler when the user is no longer active or does not exist anymore
        user_scheduler_ids = self.search(cr,SUPERUSER_ID,[])
        for scheduler_id in user_scheduler_ids:
            scheduler_user_id = self.browse(cr,SUPERUSER_ID,scheduler_id,context)
            if not scheduler_user_id.user_id.id in user_ids:
                self.unlink(cr, SUPERUSER_ID, scheduler_id, context=context)
            
        password_policy_model = self.pool.get('res.config.password_policy')
        
        
        for id in user_ids:
            pw_scheduler_user_id = self.search(cr,SUPERUSER_ID,[('user_id','=',id)])
            if not pw_scheduler_user_id:
                current_user = user_model.browse(cr,SUPERUSER_ID,id)[0]
                pw_scheduler_data = {
                                     'user_id' : id,
                                     'last_password_change' : datetime.datetime.now(),
                                     'reminder_send' : False
                                     }
                self.create(cr,SUPERUSER_ID,pw_scheduler_data)
        
        cr.commit()
        cr.close()
        
    
    def send_reminder(self,user_scheduler_id,user_id,mail_possible):
        cr = self.pool.cursor()
        context = {}
        user_model = self.pool.get('res.users')
        for user in user_model.browse(cr,SUPERUSER_ID, user_id):
            if not user.email:
                _logger.error(_("Cannot send email: %s has no email address.") % user.name)
            else:
                try:
                    if mail_possible:
                        
                        template = self.pool.get('ir.model.data').get_object(cr, SUPERUSER_ID, 'password_policy', 'change_password_reminder_email')
                        assert template._name == 'email.template'
                        self.pool.get('email.template').send_mail(cr, SUPERUSER_ID, template.id, user_scheduler_id, force_send=True, raise_exception=True, context=context)
                        user_scheduler_data = {
                                'reminder_send' : True,
                                }
                        self.write(cr,SUPERUSER_ID,user_scheduler_id,user_scheduler_data)
                        _logger.debug("Password change reminder send to %s" % user.name)
                except MailDeliveryException:
                    _logger.error(_("Mail Delivery Exception has occured. Please check outgoing email server."))
                    mail_possible = False
        cr.commit()
        cr.close()
        return mail_possible
            

    def block_login(self,user_scheduler_id,user_id,mail_possible):
        cr = self.pool.cursor()
        context = {}
        if user_id in self.get_ignore_ids(cr, SUPERUSER_ID, context):
            return
        
        for user in self.browse(cr,SUPERUSER_ID, user_scheduler_id):
            if user.login_blocked or user.user_id.id in self.get_ignore_ids(cr, SUPERUSER_ID, context):
                cr.close()
                return
            
            user_data = {
                        'login_blocked' : True,
                        }
            self.write(cr,SUPERUSER_ID,user_scheduler_id,user_data)

        user_model = self.pool.get('res.users')   
        for user in user_model.browse(cr,SUPERUSER_ID,user_id):
            user_data = {'password' : 256}
            new_context = {
                           'ignore_pw_change' : True
                           }
            user_model.write(cr,SUPERUSER_ID,user_id,user_data,new_context)
            _logger.debug("%s has been blocked until the user changes the password" % user.name)
            if not user.email:
                _logger.error(_("Cannot send email: %s has no email address.") % user.name)
            else:
                try:
                    if mail_possible:
                        
                        template = self.pool.get('ir.model.data').get_object(cr, SUPERUSER_ID, 'password_policy', 'change_password_block_email')
                        assert template._name == 'email.template'
                        self.pool.get('email.template').send_mail(cr, SUPERUSER_ID, template.id, user_scheduler_id, force_send=True, raise_exception=True, context=context)
                except MailDeliveryException:
                    _logger.error(_("Mail Delivery Exception has occured. Please check outgoing email server."))
                    mail_possible = False
  
        cr.commit()
        cr.close()
        return mail_possible






