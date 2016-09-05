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
{
    'name': 'Password Policy',
    'version': '0.1',
    'category': 'Tools',
    'description': """Open2bizz Password Policy module.""",
    'author': 'Open2bizz',
    'website': 'http://open2bizz.nl/',
    'depends': [
                'base',
                'email_template'
                ],
    'data':[
            'data/ir_cron.xml',
            'data/res.config.password_policy.csv',
            'data/password_policy_email.xml',
            'views/password_policy_view.xml',
            'views/res_config_view.xml'
           
            ],            
    'demo_xml': [],
    'installable': True,
    'auto_install': True,
}