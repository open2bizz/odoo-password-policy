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

from openerp import models, SUPERUSER_ID
from openerp.tools import DEFAULT_SERVER_DATETIME_FORMAT
from openerp.tools.translate import _
from openerp.exceptions import except_orm
from datetime import datetime, timedelta
import logging
_logger = logging.getLogger(__name__)

class PasswordRules(models.Model):
    _name = 'password.rules'
    _auto = False
    
    def check_password_rules(self,cr,uid, password,context=None):
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