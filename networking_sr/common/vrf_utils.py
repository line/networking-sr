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


from neutron_lib import constants
from neutron_lib import context as lib_context
from neutron_lib.db import api as db_api
from neutron_lib import exceptions
from neutron_lib.plugins import directory
from oslo_log import log as logging
from oslo_utils import uuidutils

from neutron._i18n import _

from networking_sr.ml2 import type_srv6
from networking_sr.ml2 import type_srv6vrf


LOG = logging.getLogger(__name__)


class VrfNetworkNotFound(exceptions.NotFound):
    message = _("VRF network could not be found.")


class VrfNetworkSubnetNotFound(exceptions.NotFound):
    message = _("Subnet for VRF network could not be found.")


class VrfPortNotFound(exceptions.NotFound):
    message = _("VRF port could not be found.")


class VrfNetworkAlreadyExists(exceptions.Conflict):
    message = _("VRF network already exists.")


def get_vrf_name(network_type, project_id, network_id):
    if network_type == type_srv6.SRV6:
        vrf = "vrf" + project_id[:6] + network_id[:6]
    elif network_type == type_srv6vrf.SRV6VRF:
        return
    else:
        LOG.error("Invalid network type: %s", network_type)
        return
    return vrf


class VrfIpAllocation(object):
    def __init__(self):
        networks = self._get_vrf_network()
        if not networks:
            raise VrfNetworkNotFound
        self.vrf_network_id = networks[0]['id']
        self.vrf_project_id = networks[0]['project_id']

    def _get_vrf_network(self):
        plugin = directory.get_plugin()
        context = lib_context.get_admin_context()
        networks = plugin.get_networks(
            context,
            filters={"provider:network_type": [type_srv6vrf.SRV6VRF]})
        return networks

    def create_vrf_ip(self, context, vrf_name):
        plugin = directory.get_plugin()
        port_db = {'port': {'name': vrf_name,
                            'tenant_id': self.vrf_project_id,
                            'device_owner': 'vrf',
                            'device_id': uuidutils.generate_uuid(),
                            'mac_address': constants.ATTR_NOT_SPECIFIED,
                            'admin_state_up': True,
                            'network_id': self.vrf_network_id,
                            'fixed_ips': constants.ATTR_NOT_SPECIFIED}}
        result = plugin.create_port_db(context.elevated(), port_db)
        if not result['fixed_ips']:
            raise VrfNetworkSubnetNotFound
        return result

    @db_api.retry_if_session_inactive()
    def _delete_port(self, context, plugin, port_id):
        with db_api.CONTEXT_WRITER.using(context):
            plugin.ipam.delete_port(context, port_id)

    def delete_vrf_ip(self, context, vrf):
        plugin = directory.get_plugin()
        vrf_ports = plugin.get_ports(context.elevated(),
                                     filters={'name': [vrf]})
        if not vrf_ports:
            return
        else:
            vrf_port = vrf_ports[0]
        try:
            self._delete_port(context.elevated(), plugin, vrf_port['id'])
        except exceptions.PortNotFound:
            # Already the port was removed
            pass
