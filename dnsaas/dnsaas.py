#   Copyright 2012-2013 STACKOPS TECHNOLOGIES S.L.
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.

from fabric.api import *
from cuisine import *
import fabuloso.utils as utils

DESIGNATE_CONF = '/etc/designate/designate.conf'
POWERDNS_CONF = '/etc/powerdns/pdns.d/pdns.local.gmysql'

REPOS = (
    # Setting first to highest priority
    'deb http://repos.stackops.net/ havana-dev main',
    #'deb http://repos.stackops.net/ havana main',
    #'deb http://repos.stackops.net/ havana-updates main',
    #'deb http://repos.stackops.net/ havana-security main',
    #'deb http://repos.stackops.net/ havana-backports main',
    'deb http://us.archive.ubuntu.com/ubuntu/ precise main universe',
    'deb http://us.archive.ubuntu.com/ubuntu/ precise-security main universe',
    'deb http://us.archive.ubuntu.com/ubuntu/ precise-updates main universe',
    'deb http://ubuntu-cloud.archive.canonical.com/ubuntu precise-updates/havana main')

def install_packages():
    sudo('pdns-backend-mysql pdns-backend-mysql/dbconfig-install boolean false '
         '| debconf-set-selections')
    package_ensure('python-amqp')
    package_ensure('pdns-server')
    package_ensure('pdns-backend-mysql')
    package_ensure('designateclient')
    package_ensure('designate-api')
    package_ensure('designate-central')


def install():
    add_repos()
    install_packages()

def start():
    stop()
    pdns_start()
    designate_api_start()
    designate_central_start()

def stop():
    pdns_stop()
    designate_api_stop()
    designate_central_stop()

def pdns_start():
    pdns_stop()
    sudo("service pdns start")

def pdns_stop():
    sudo("service pdns stop")

def designate_api_start():
    designate_api_stop()

def designate_api_stop():
    sudo("service designate-api stop")

def designate_central_start():
    designate_central_stop()
    sudo("service designate-central start")

def designate_central_stop():
    sudo("service designate-central stop")

def add_repos():
    """Clean and Add necessary repositories and updates"""

    package_ensure('python-software-properties')
    sudo('apt-add-repository --yes ppa:designate-ppa/havana')
    sudo('apt-get -y update')
    sudo('sudo apt-get upgrade --yes')


def set_config_file(mysql_username='designate', mysql_password='stackops',
                    mysql_host='127.0.0.1', mysql_port='3306',
                    mysql_schema_designate ='designate',
                    mysql_schema_powerdns ='powerdns', user='designate',
                    password='stackops', auth_host='127.0.0.1',
                    auth_port='35357', auth_protocol='http', tenant='service'):
    utils.set_option(DESIGNATE_CONF, 'service:api',
                     'auth_strategy', 'keystone')
    utils.set_option(DESIGNATE_CONF, 'service:api',
                     'enabled_extensions_v1',
                     'diagnostics, quotas, reports, sync')
    utils.set_option(DESIGNATE_CONF, 'admin_tenant_name',
                     tenant, section='keystone_authtoken')
    utils.set_option(DESIGNATE_CONF, 'admin_user',
                     user, section='keystone_authtoken')
    utils.set_option(DESIGNATE_CONF, 'admin_password',
                     password, section='keystone_authtoken')
    utils.set_option(DESIGNATE_CONF, 'auth_host', auth_host,
                     section='keystone_authtoken')
    utils.set_option(DESIGNATE_CONF, 'auth_port', auth_port,
                     section='keystone_authtoken')
    utils.set_option(DESIGNATE_CONF, 'auth_protocol', auth_protocol,
                     section='keystone_authtoken')
    utils.set_option(DESIGNATE_CONF, 'auth_protocol', auth_protocol,
                     section='keystone_authtoken')
    auth_uri = 'http://' + auth_host + ':5000/v2.0'
    utils.set_option(DESIGNATE_CONF, 'auth_uri',
                     auth_uri, section='keystone_authtoken')
    utils.set_option(DESIGNATE_CONF, 'backend_driver',
                     'powerdns', section='service:central')
    utils.set_option(DESIGNATE_CONF, 'database_connection',
                     utils.sql_connect_string(mysql_host,
                                              mysql_password,
                                              mysql_port,
                                              mysql_schema_designate,
                                              mysql_username),
                     section='storage:sqlalchemy')
    utils.set_option(DESIGNATE_CONF, 'database_connection',
                     utils.sql_connect_string(mysql_host,
                                              mysql_password,
                                              mysql_port,
                                              mysql_schema_powerdns,
                                              mysql_username),
                     section='storage:sqlalchemy')
    sudo('designate-manage database-init')
    sudo('designate-manage database-sync')
    sudo('designate-manage powerdns database-init')
    sudo('designate-manage powerdns database-sync')

    #PowerDNS configuration
    utils.set_option(POWERDNS_CONF, 'launch', 'gmysql')
    utils.set_option(POWERDNS_CONF, 'gmysql-host', mysql_host)
    utils.set_option(POWERDNS_CONF, 'gmysql-port', mysql_port)
    utils.set_option(POWERDNS_CONF, 'gmysql-dbname', mysql_schema_powerdns)
    utils.set_option(POWERDNS_CONF, 'gmysql-user', mysql_username)
    utils.set_option(POWERDNS_CONF, 'gmysql-password', mysql_password)
    utils.set_option(POWERDNS_CONF, 'gmysql-dnssec', 'yes')