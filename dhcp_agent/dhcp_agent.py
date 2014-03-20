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
from cuisine import *
from fabric.api import *

import fabuloso.utils as utils

NEUTRON_API_PASTE_CONF = '/etc/neutron/api-paste.ini'

DHCP_AGENT_CONF = '/etc/neutron/dhcp_agent.ini'

NEUTRON_CONF = '/etc/neutron/neutron.conf'

def neutron_dhcp_agent_stop():
    with settings(warn_only=True):
        sudo("service neutron-dhcp-agent stop")


def neutron_dhcp_agent_start():
    neutron_dhcp_agent_stop()
    sudo("service neutron-dhcp-agent start")


def stop():
    neutron_dhcp_agent_stop()


def start():
    neutron_dhcp_agent_start()


def configure_ubuntu_packages():
    """Configure dhcp agent related packages"""
    package_ensure('python-amqp')
    package_ensure('neutron-dhcp-agent')
    package_ensure('python-pyparsing')
    package_ensure('python-mysqldb')
    package_ensure('python-neutronclient')


def uninstall_ubuntu_packages():
    """Uninstall openvswitch and neutron packages"""
    package_clean('python-amqp')
    package_clean('neutron-dhcp-agent')
    package_clean('python-pyparsing')
    package_clean('python-mysqldb')
    package_clean('python-neutronclient')


def install(cluster=False):
    """Generate neutron configuration. Execute on both servers"""
    configure_ubuntu_packages()
    sudo('update-rc.d neutron-dhcp-agent defaults 98 02')


def post_configuration(default_enable=False, user='neutron', password='stackops',
                      auth_host='127.0.0.1', tenant='service'):
    if not default_enable:
        disable_dhcp_agent(user, password, auth_host, tenant)


def configure_dhcp_agent(name_server='8.8.8.8'):
    utils.set_option(DHCP_AGENT_CONF, 'use_namespaces', 'True')
    utils.set_option(DHCP_AGENT_CONF, 'dnsmasq_dns_server', name_server)
    utils.set_option(DHCP_AGENT_CONF, 'dhcp_driver',
                     'neutron.agent.linux.dhcp.Dnsmasq')
    utils.set_option(DHCP_AGENT_CONF, 'interface_driver',
                     'neutron.agent.linux.interface.OVSInterfaceDriver')
    #utils.set_option(DHCP_AGENT_CONF, 'ovs_use_veth', 'True')


def set_config_file(user='neutron', password='stackops', auth_host='127.0.0.1',
                    auth_port='35357', auth_protocol='http', tenant='service',
                    rabbit_password='guest', rabbit_host='127.0.0.1',
                    mysql_username='neutron', mysql_password='stackops',
                    mysql_schema='neutron', mysql_host='127.0.0.1',
                    mysql_port='3306'):

    utils.set_option(NEUTRON_API_PASTE_CONF, 'admin_tenant_name',
                     tenant, section='filter:authtoken')
    utils.set_option(NEUTRON_API_PASTE_CONF, 'admin_user',
                     user, section='filter:authtoken')
    utils.set_option(NEUTRON_API_PASTE_CONF, 'admin_password',
                     password, section='filter:authtoken')
    utils.set_option(NEUTRON_API_PASTE_CONF, 'auth_host', auth_host,
                     section='filter:authtoken')
    utils.set_option(NEUTRON_API_PASTE_CONF, 'auth_port', auth_port,
                     section='filter:authtoken')
    utils.set_option(NEUTRON_API_PASTE_CONF, 'auth_protocol', auth_protocol,
                     section='filter:authtoken')
    auth_uri = 'http://' + auth_host + ':5000'
    utils.set_option(NEUTRON_API_PASTE_CONF, 'auth_uri',
                     auth_uri, section='filter:authtoken')
    cp = 'neutron.plugins.ml2.plugin.Ml2Plugin'
    utils.set_option(NEUTRON_CONF, 'core_plugin', cp)
    utils.set_option(NEUTRON_CONF, 'auth_strategy', 'keystone')
    utils.set_option(NEUTRON_CONF, 'fake_rabbit', 'False')
    utils.set_option(NEUTRON_CONF, 'rabbit_password', rabbit_password)
    utils.set_option(NEUTRON_CONF, 'rabbit_host', rabbit_host)
    utils.set_option(NEUTRON_CONF, 'notification_driver',
                     'neutron.openstack.common.notifier.rpc_notifier')
    utils.set_option(NEUTRON_CONF, 'notification_topics',
                     'notifications,monitor')
    utils.set_option(NEUTRON_CONF, 'default_notification_level', 'INFO')
    utils.set_option(NEUTRON_CONF, 'core_plugin', cp)
    utils.set_option(NEUTRON_CONF, 'connection', utils.sql_connect_string(
        mysql_host, mysql_password, mysql_port, mysql_schema, mysql_username),
                     section='database')
    utils.set_option(NEUTRON_CONF, 'admin_tenant_name',
                     tenant, section='keystone_authtoken')
    utils.set_option(NEUTRON_CONF, 'admin_user',
                     user, section='keystone_authtoken')
    utils.set_option(NEUTRON_CONF, 'admin_password',
                     password, section='keystone_authtoken')
    utils.set_option(NEUTRON_CONF, 'auth_host', auth_host,
                     section='keystone_authtoken')
    utils.set_option(NEUTRON_CONF, 'auth_port', auth_port,
                     section='keystone_authtoken')
    utils.set_option(NEUTRON_CONF, 'auth_protocol', auth_protocol,
                     section='keystone_authtoken')
    utils.set_option(NEUTRON_CONF, 'auth_protocol', auth_protocol,
                     section='keystone_authtoken')
    utils.set_option(NEUTRON_CONF, 'allow_overlapping_ips', 'True')


def get_agent_id (user='neutron', password='stackops', auth_host='127.0.0.1',
                  tenant='service'):
    auth_uri = 'http://' + auth_host + ':5000/v2.0'
    stdout = sudo("neutron --os-auth-url %s --os-username %s --os-password %s "
                  "--os-tenant-name %s --insecure --endpoint-type internalURL "
                  "agent-list | grep `hostname` |  grep 'DHCP agent' | awk '/ | "
                  "/ { print $2 }'"
                  % (auth_uri, user, password, tenant))
    puts(stdout)
    return stdout.replace('\n', '')


def enable_dhcp_agent(user='neutron', password='stackops',
                      auth_host='127.0.0.1', tenant='service'):
    auth_uri = 'http://' + auth_host + ':5000/v2.0'
    agent_id = get_agent_id(user, password, auth_host, tenant)
    sudo("neutron --os-auth-url %s --os-username %s --os-password %s "
         "--os-tenant-name %s --insecure --endpoint-type internalURL "
         "agent-update %s --admin-state-up True"
         % (auth_uri, user, password, tenant, agent_id))

def disable_dhcp_agent(user='neutron', password='stackops',
                      auth_host='127.0.0.1', tenant='service'):
    auth_uri = 'http://' + auth_host + ':5000/v2.0'
    agent_id = get_agent_id(user, password, auth_host, tenant)
    sudo("neutron --os-auth-url %s --os-username %s --os-password %s "
         "--os-tenant-name %s --insecure --endpoint-type internalURL "
         "agent-update %s --admin-state-up False"
         % (auth_uri, user, password, tenant, agent_id))

