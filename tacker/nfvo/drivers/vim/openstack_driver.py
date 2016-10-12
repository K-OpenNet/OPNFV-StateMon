# Copyright 2016 Brocade Communications System, Inc.
# All Rights Reserved.
#
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import os
import six

from keystoneclient.auth.identity import v2
from keystoneclient.auth.identity import v3
from keystoneclient import exceptions
from keystoneclient import session
from neutronclient.v2_0 import client as neutron_client
from oslo_config import cfg
from oslo_log import log as logging

from tacker._i18n import _LW, _
from tacker.agent.linux import utils as linux_utils
from tacker.common import log
from tacker.common import clients
from tacker.extensions import nfvo
from tacker.nfvo.drivers.vim import abstract_vim_driver
from tacker.vnfm import keystone


LOG = logging.getLogger(__name__)
CONF = cfg.CONF

OPTS = [cfg.StrOpt('openstack', default='/etc/tacker/vim/fernet_keys',
                   help='Dir.path to store fernet keys.')]

# same params as we used in ping monitor driver
OPENSTACK_OPTS = [
    cfg.StrOpt('count', default='1',
               help=_('number of ICMP packets to send')),
    cfg.StrOpt('timeout', default='1',
               help=_('number of seconds to wait for a response')),
    cfg.StrOpt('interval', default='1',
               help=_('number of seconds to wait between packets'))
]
cfg.CONF.register_opts(OPTS, 'vim_keys')
cfg.CONF.register_opts(OPENSTACK_OPTS, 'vim_monitor')

_VALID_RESOURCE_TYPES = {'network': {'client': neutron_client.Client,
                                     'cmd': 'list_'
                                     }
                         }


def config_opts():
    return [('vim_keys', OPTS), ('vim_monitor', OPENSTACK_OPTS)]


class OpenStack_Driver(abstract_vim_driver.VimAbstractDriver):
    """Driver for OpenStack VIM

    OpenStack driver handles interactions with local as well as
    remote OpenStack instances. The driver invokes keystone service for VIM
    authorization and validation. The driver is also responsible for
    discovering placement attributes such as regions, availability zones
    """

    def __init__(self):
        self.keystone = keystone.Keystone()
        self.keystone.create_key_dir(CONF.vim_keys.openstack)

    def get_type(self):
        return 'openstack'

    def get_name(self):
        return 'OpenStack VIM Driver'

    def get_description(self):
        return 'OpenStack VIM Driver'

    def authenticate_vim(self, vim_obj):
        """Validate VIM auth attributes

        Initialize keystoneclient with provided authentication attributes.
        """
        auth_url = vim_obj['auth_url']
        keystone_version = self._validate_auth_url(auth_url)
        auth_cred = self._get_auth_creds(keystone_version, vim_obj)
        return self._initialize_keystone(keystone_version, auth_cred)

    def _get_auth_creds(self, keystone_version, vim_obj):
        auth_url = vim_obj['auth_url']
        auth_cred = vim_obj['auth_cred']
        vim_project = vim_obj['vim_project']

        if keystone_version not in auth_url:
            vim_obj['auth_url'] = auth_url + '/' + keystone_version
        if keystone_version == 'v3':
            auth_cred['project_id'] = vim_project.get('id')
            auth_cred['project_name'] = vim_project.get('name')
            auth_cred['project_domain_name'] = vim_project.get(
                'project_domain_name')
        else:
            auth_cred['tenant_id'] = vim_project.get('id')
            auth_cred['tenant_name'] = vim_project.get('name')
            # pop stuff not supported in keystone v2
            auth_cred.pop('user_domain_name', None)
            auth_cred.pop('user_id', None)
        auth_cred['auth_url'] = vim_obj['auth_url']
        return auth_cred

    def _get_auth_plugin(self, version, **kwargs):
        if version == 'v2.0':
            auth_plugin = v2.Password(**kwargs)
        else:
            auth_plugin = v3.Password(**kwargs)

        return auth_plugin

    def _validate_auth_url(self, auth_url):
        try:
            keystone_version = self.keystone.get_version(auth_url)
        except Exception as e:
            LOG.error(_('VIM Auth URL invalid'))
            raise nfvo.VimConnectionException(message=e.message)
        return keystone_version

    def _initialize_keystone(self, version, auth):
        ks_client = self.keystone.initialize_client(version=version, **auth)
        return ks_client

    def _find_regions(self, ks_client):
        if ks_client.version == 'v2.0':
            service_list = ks_client.services.list()
            heat_service_id = None
            for service in service_list:
                if service.type == 'orchestration':
                    heat_service_id = service.id
            endpoints_list = ks_client.endpoints.list()
            region_list = [endpoint.region for endpoint in
                           endpoints_list if endpoint.service_id ==
                           heat_service_id]
        else:
            region_info = ks_client.regions.list()
            region_list = [region.id for region in region_info]
        return region_list

    def discover_placement_attr(self, vim_obj, ks_client):
        """Fetch VIM placement information

        Attributes can include regions, AZ.
        """
        try:
            regions_list = self._find_regions(ks_client)
        except (exceptions.Unauthorized, exceptions.BadRequest) as e:
            LOG.warn(_("Authorization failed for user"))
            raise nfvo.VimUnauthorizedException(message=e.message)
        vim_obj['placement_attr'] = {'regions': regions_list}
        return vim_obj

    @log.log
    def register_vim(self, vim_obj):
        """Validate and register VIM

        Store VIM information in Tacker for
        VNF placements
        """
        ks_client = self.authenticate_vim(vim_obj)
        self.discover_placement_attr(vim_obj, ks_client)
        self.encode_vim_auth(vim_obj['id'], vim_obj['auth_cred'])
        LOG.debug(_('VIM registration completed for %s'), vim_obj)

    @log.log
    def deregister_vim(self, vim_id):
        """Deregister VIM from NFVO

        Delete VIM keys from file system
        """
        self.delete_vim_auth(vim_id)

    @log.log
    def delete_vim_auth(self, vim_id):
        """Delete vim information

         Delete vim key stored in file system
         """
        LOG.debug(_('Attempting to delete key for vim id %s'), vim_id)
        key_file = os.path.join(CONF.vim_keys.openstack, vim_id)
        try:
            os.remove(key_file)
            LOG.debug(_('VIM key deleted successfully for vim %s'), vim_id)
        except OSError:
            LOG.warning(_('VIM key deletion unsuccessful for vim %s'), vim_id)

    @log.log
    def encode_vim_auth(self, vim_id, auth):
        """Encode VIM credentials

         Store VIM auth using fernet key encryption
         """
        fernet_key, fernet_obj = self.keystone.create_fernet_key()
        encoded_auth = fernet_obj.encrypt(auth['password'].encode('utf-8'))
        auth['password'] = encoded_auth
        key_file = os.path.join(CONF.vim_keys.openstack, vim_id)
        try:
            with open(key_file, 'w') as f:
                if six.PY2:
                    f.write(fernet_key.decode('utf-8'))
                else:
                    f.write(fernet_key)
                LOG.debug(_('VIM auth successfully stored for vim %s'), vim_id)
        except IOError:
            raise nfvo.VimKeyNotFoundException(vim_id=vim_id)

    @log.log
    def vim_status(self, auth_url):
        """Checks the VIM health status"""
        vim_ip = auth_url.split("//")[-1].split(":")[0].split("/")[0]
        ping_cmd = ['ping',
                    '-c', cfg.CONF.vim_monitor.count,
                    '-W', cfg.CONF.vim_monitor.timeout,
                    '-i', cfg.CONF.vim_monitor.interval,
                    vim_ip]

        try:
            linux_utils.execute(ping_cmd, check_exit_code=True)
            return True
        except RuntimeError:
            LOG.warning(_LW("Cannot ping ip address: %s"), vim_ip)
            return False

    @log.log
    def get_vim_resource_id(self, vim_obj, resource_type, resource_name):
        """Locates openstack resource by type/name and returns ID

        :param vim_obj: VIM info used to access openstack instance
        :param resource_type: type of resource to find
        :param resource_name: name of resource to locate
        :return: ID of resource
        """
        if resource_type in _VALID_RESOURCE_TYPES.keys():
            client_type = _VALID_RESOURCE_TYPES[resource_type]['client']
            cmd_prefix = _VALID_RESOURCE_TYPES[resource_type]['cmd']
        else:
            raise nfvo.VimUnsupportedResourceTypeException(type=resource_type)

        client = self._get_client(vim_obj, client_type)
        cmd = str(cmd_prefix) + str(resource_name)
        try:
            resources = getattr(client, "%s" % cmd)()
            LOG.debug(_('resources output %s'), resources)
            for resource in resources[resource_type]:
                if resource['name'] == resource_name:
                    return resource['id']
        except Exception:
            raise nfvo.VimGetResourceException(cmd=cmd, type=resource_type)

    @log.log
    def _get_client(self, vim_obj, client_type):
        """Initializes and returns an openstack client

        :param vim_obj: VIM Information
        :param client_type: openstack client to initialize
        :return: initialized client
        """
        auth_url = vim_obj['auth_url']
        keystone_version = self._validate_auth_url(auth_url)
        auth_cred = self._get_auth_creds(keystone_version, vim_obj)
        auth_plugin = self._get_auth_plugin(keystone_version, **auth_cred)
        sess = session.Session(auth=auth_plugin)
        return client_type(session=sess)


    @log.log
    def create_lb(self, vnf, auth_attr):
        """Create a LBaaS instance"""
        region_name = vnf.get('placement_attr', {}).get('region_name', None)
        neutronclient_ = NeutronClient(auth_attr, region_name)
        neutronclient_.loadbalancer_create



class NeutronClient(object):
    def __init__(self, auth_attr, region_name=None):
        # context, password are unused
        self.neutron = clients.OpenstackClients(auth_attr, region_name).neutron

    def network_get(self, name_or_id, ignore_missing=False):
        network = self.neutron.find_network(name_or_id, ignore_missing)
        return network

    def port_find(self, name_or_id, ignore_missing=False):
        port = self.neutron.find_port(name_or_id, ignore_missing)
        return port

    def subnet_get(self, name_or_id, ignore_missing=False):
        subnet = self.neutron.find_subnet(name_or_id, ignore_missing)
        return subnet

    def loadbalancer_get(self, name_or_id, ignore_missing=False):
        lb = self.neutron.find_load_balancer(name_or_id, ignore_missing)
        return lb

    def loadbalancer_create(self, vip_subnet_id, vip_address=None,
                            admin_state_up=True, name=None, description=None):

        kwargs = {
            'vip_subnet_id': vip_subnet_id,
            'admin_state_up': admin_state_up,
        }

        if vip_address is not None:
            kwargs['vip_address'] = vip_address
        if name is not None:
            kwargs['name'] = name
        if description is not None:
            kwargs['description'] = description

        res = self.neutron.create_load_balancer(**kwargs)
        return res

    def loadbalancer_delete(self, lb_id, ignore_missing=True):
        self.neutron.delete_load_balancer(
            lb_id, ignore_missing=ignore_missing)
        return

    def listener_create(self, loadbalancer_id, protocol, protocol_port,
                        connection_limit=None,
                        admin_state_up=True, name=None, description=None):

        kwargs = {
            'loadbalancer_id': loadbalancer_id,
            'protocol': protocol,
            'protocol_port': protocol_port,
            'admin_state_up': admin_state_up,
        }

        if connection_limit is not None:
            kwargs['connection_limit'] = connection_limit
        if name is not None:
            kwargs['name'] = name
        if description is not None:
            kwargs['description'] = description

        res = self.neutron.create_listener(**kwargs)
        return res

    def listener_delete(self, listener_id, ignore_missing=True):
        self.neutron.delete_listener(listener_id,
                                          ignore_missing=ignore_missing)
        return

    def pool_create(self, lb_algorithm, listener_id, protocol,
                    admin_state_up=True, name=None, description=None):

        kwargs = {
            'lb_algorithm': lb_algorithm,
            'listener_id': listener_id,
            'protocol': protocol,
            'admin_state_up': admin_state_up,
        }

        if name is not None:
            kwargs['name'] = name
        if description is not None:
            kwargs['description'] = description

        res = self.neutron.create_pool(**kwargs)
        return res

    def pool_delete(self, pool_id, ignore_missing=True):
        self.neutron.delete_pool(pool_id,
                                      ignore_missing=ignore_missing)
        return

    def pool_member_create(self, pool_id, address, protocol_port, subnet_id,
                           weight=None, admin_state_up=True):

        kwargs = {
            'address': address,
            'protocol_port': protocol_port,
            'admin_state_up': admin_state_up,
            'subnet_id': subnet_id,
        }

        if weight is not None:
            kwargs['weight'] = weight

        res = self.neutron.create_pool_member(pool_id, **kwargs)
        return res

    def pool_member_delete(self, pool_id, member_id, ignore_missing=True):
        self.neutron.delete_pool_member(
            member_id, pool_id, ignore_missing=ignore_missing)
        return

    def healthmonitor_create(self, hm_type, delay, timeout, max_retries,
                             pool_id, admin_state_up=True,
                             http_method=None, url_path=None,
                             expected_codes=None):
        kwargs = {
            'type': hm_type,
            'delay': delay,
            'timeout': timeout,
            'max_retries': max_retries,
            'pool_id': pool_id,
            'admin_state_up': admin_state_up,
        }

        # TODO(anyone): verify if this is correct
        if hm_type == 'HTTP':
            if http_method is not None:
                kwargs['http_method'] = http_method
            if url_path is not None:
                kwargs['url_path'] = url_path
            if expected_codes is not None:
                kwargs['expected_codes'] = expected_codes

        res = self.neutron.create_health_monitor(**kwargs)
        return res

    def healthmonitor_delete(self, hm_id, ignore_missing=True):
        self.neutron.delete_health_monitor(
            hm_id, ignore_missing=ignore_missing)
        return

        

