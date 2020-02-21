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

from neutron_lib.agent import topics
from neutron_lib.api.definitions import portbindings
from neutron_lib import constants
from neutron_lib import exceptions as n_exc
from neutron_lib.plugins import directory
from neutron_lib.plugins.ml2 import api
from neutron_lib.plugins import utils
from oslo_log import log as logging
from oslo_serialization import jsonutils

from neutron.agent import securitygroups_rpc
from neutron.plugins.ml2.drivers import mech_agent

from networking_sr.agent import rpc as sr_rpc
from networking_sr.common import vrf_utils
from networking_sr.ml2 import type_srv6
from networking_sr.ml2 import type_srv6vrf

LOG = logging.getLogger(__name__)
AGENT_TYPE_SR = "SR agent"


class SrMechanismDriver(mech_agent.SimpleAgentMechanismDriverBase):

    def __init__(self):
        sg_enabled = securitygroups_rpc.is_firewall_enabled()
        super(SrMechanismDriver, self).__init__(
            AGENT_TYPE_SR,
            portbindings.VIF_TYPE_TAP,
            {portbindings.CAP_PORT_FILTER: sg_enabled})
        self.sr_rpc_api = sr_rpc.SrAgentApi(topics.AGENT)
        self.vrf_allocation = None

    def get_allowed_network_types(self, agent=None):
        return [type_srv6.SRV6, type_srv6vrf.SRV6VRF]

    def get_mappings(self, agent):
        pass

    def check_segment_for_agent(self, segment, agent):
        """Check if segment can be bound for agent.

        :param segment: segment dictionary describing segment to bind
        :param agent: agents_db entry describing agent to bind
        :returns: True iff segment can be bound for agent

        Called outside any transaction during bind_port so that derived
        MechanismDrivers can use agent_db data along with built-in
        knowledge of the corresponding agent's capabilities to
        determine whether or not the specified network segment can be
        bound for the agent.
        """

        allowed_network_types = self.get_allowed_network_types(agent)

        LOG.debug("Checking segment: %(segment)s "
                  "with network types: %(network_types)s",
                  {'segment': segment,
                   'network_types': allowed_network_types})

        network_type = segment[api.NETWORK_TYPE]
        if network_type not in allowed_network_types:
            LOG.debug(
                'Network %(network_id)s with segment %(id)s is type '
                'of %(network_type)s but agent %(agent)s or mechanism driver '
                'only support %(allowed_network_types)s.',
                {'network_id': segment['network_id'],
                 'id': segment['id'],
                 'network_type': network_type,
                 'agent': agent['host'],
                 'allowed_network_types': allowed_network_types})
            return False

        return True

    def _create_vrf_ip(self, context, vrf):
        if self.vrf_allocation is None:
            self.vrf_allocation = vrf_utils.VrfIpAllocation()
        try:
            vrf_port = self.vrf_allocation.create_vrf_ip(context, vrf)
        except n_exc.NetworkNotFound:
            # An old vrf network might be deleted. Try to get a new one
            self.vrf_allocation = vrf_utils.VrfIpAllocation()
            vrf_port = self.vrf_allocation.create_vrf_ip(vrf)
        return vrf_port

    def _delete_vrf_ip(self, context, vrf):
        # The mech_sr might be restarted
        if self.vrf_allocation is None:
            self.vrf_allocation = vrf_utils.VrfIpAllocation()
        self.vrf_allocation.delete_vrf_ip(context, vrf)

    def create_network_precommit(self, context):
        network = context.current
        if network['provider:network_type'] != type_srv6vrf.SRV6VRF:
            return
        if self.vrf_allocation is None:
            try:
                self.vrf_allocation = vrf_utils.VrfIpAllocation()
            except vrf_utils.VrfNetworkNotFound:
                return
        raise vrf_utils.VrfNetworkAlreadyExists

    def create_network_postcommit(self, context):
        # Adds a logic to pass vrf create event to gateway agent if needed
        pass

    def delete_network_postcommit(self, context):
        plugin_context = context._plugin_context
        network = context.current
        vrf = vrf_utils.get_vrf_name(network["provider:network_type"],
                                     network["project_id"],
                                     network["id"])
        self.sr_rpc_api.vrf_delete(plugin_context, vrf)
        self._delete_vrf_ip(plugin_context, vrf)

    def update_port_precommit(self, context):
        # This mech doesn't check whether port is binded to VM so
        # the mech treats all ports as VM's port
        plugin = directory.get_plugin()
        port_id = context.current["id"]
        port_db = plugin._get_port(context._plugin_context, port_id)
        cur_binding = utils.get_port_binding_by_status_and_host(
            port_db.port_bindings, constants.ACTIVE)
        agents = context.host_agents(self.agent_type)
        network_id = port_db.network_id
        node_id = None
        if agents:
            # SR plugin expects to return just one sr_agent
            agent = agents[0]
            if agent["alive"]:
                node_id = agent["configurations"].get("segment_node_id")
        if self._is_required_to_update_binding_profile(context, node_id):
            # Specify vrf name
            network = plugin.get_network(context._plugin_context,
                                         network_id)
            network_type = network["provider:network_type"]
            project_id = port_db.project_id
            vrf = vrf_utils.get_vrf_name(network_type, project_id, network_id)
            if not vrf:
                return
            # Prepare vrf port info
            vrf_ports = plugin.get_ports(context._plugin_context,
                                         filters={'name': [vrf]})
            if not vrf_ports:
                vrf_port = self._create_vrf_ip(context._plugin_context, vrf)
            else:
                vrf_port = vrf_ports[0]
            vrf_ip = vrf_port['fixed_ips'][0]['ip_address']
            subnet = plugin.get_subnet(context._plugin_context,
                                       vrf_port['fixed_ips'][0]['subnet_id'])
            cidr = subnet['cidr']

            # update DB
            cur_binding.profile = jsonutils.dumps({"segment_node_id": node_id,
                                                   "vrf": vrf,
                                                   "vrf_ip": vrf_ip,
                                                   "vrf_cidr": cidr})
        if context.host == context.original_host:
            return
        self._insert_provisioning_block(context)

    def update_port_postcommit(self, context):
        port = context.current
        if port["status"] != constants.PORT_STATUS_ACTIVE:
            # TODO(hichihara): Treat with port status DOWN,
            # for example, VM shutdown case.
            return
        # Notify encap_update to all agents
        self.sr_rpc_api.encap_update(context._plugin_context, port)

    def delete_port_postcommit(self, context):
        plugin_context = context._plugin_context
        port = context.current
        self.sr_rpc_api.encap_delete(plugin_context, port)

    def _is_required_to_update_binding_profile(self, context, node_id):
        # If node_id is None, the agent running on that Host is not
        # srv6 node
        if node_id is None:
            return False

        if context._binding.profile:
            # If binding profile is already configured
            # and current host is same as new host,
            # we don't need to update binding profile
            if context.host == context.original_host:
                return False
        else:
            # If binding profile is not configure but
            # status is already ACTIVE, this port somehow
            # got active without binding profile so leave it as is

            # NOTE(Yuki Nishiwaki): Honestly I'm not sure which case
            # this condition try to cover and I think we don't need
            # this condition and safe to try to update binding profile
            # always when binding profile is missing,
            # But this condition itself is not so harm, that's why leave it
            # here
            if context.current["status"] != constants.PORT_STATUS_DOWN:
                return False

        return True
