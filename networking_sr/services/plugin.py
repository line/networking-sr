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
from neutron_lib.plugins import directory
from neutron_lib.services import base
from oslo_log import log as logging

from networking_sr.agent import rpc as sr_rpc
from networking_sr.common import vrf_utils
from networking_sr.db import srv6_encap_net_db as encap_db
from networking_sr.extensions import srv6_encap_network

LOG = logging.getLogger(__name__)


class SRv6EncapNetworkPlugin(base.ServicePluginBase,
                             encap_db.SRv6EncapNetworkDbMixin):

    supported_extension_aliases = [srv6_encap_network.ALIAS]

    def __init__(self):
        super(SRv6EncapNetworkPlugin, self).__init__()
        self.sr_rpc_api = sr_rpc.SrAgentApi(topics.AGENT)
        self.vrf_allocation = None

    def get_plugin_type(self):
        return "srv6-encap-network"

    def get_plugin_description(self):
        return "SRv6 Encap Network service plugin"

    def get_srv6_encap_networks(self, context, filters=None,
                                fields=None, sorts=None, limit=None,
                                marker=None, page_reverse=False):
        return super(SRv6EncapNetworkPlugin, self).get_srv6_encap_networks(
            context, filters=filters, fields=fields,
            sorts=sorts, limit=limit, marker=marker,
            page_reverse=page_reverse)

    def get_srv6_encap_network(self, context, encap_net_id, fields=None):
        return super(SRv6EncapNetworkPlugin, self).get_srv6_encap_network(
            context, encap_net_id, fields=fields)

    def _make_encap_rule_rpc_content(self, context, encap_net):
        plugin = directory.get_plugin()
        network = plugin.get_network(context, encap_net['network_id'])
        vrf = vrf_utils.get_vrf_name(network["provider:network_type"],
                                     encap_net['project_id'],
                                     encap_net['network_id'])
        encap_info = {'id': encap_net['id'],
                      'vrf': vrf,
                      'rules': encap_net['encap_rules']}
        return encap_info

    def create_srv6_encap_network(self, context, srv6_encap_network):
        encap_net = super(SRv6EncapNetworkPlugin,
                          self).create_srv6_encap_network(
                              context, srv6_encap_network)
        encap_info = self._make_encap_rule_rpc_content(context, encap_net)
        self.sr_rpc_api.encap_rule_update(context, encap_info)
        return encap_net

    def update_srv6_encap_network(self, context, encap_net_id,
                                  srv6_encap_network):
        encap_net = super(SRv6EncapNetworkPlugin,
                          self).update_srv6_encap_network(
                              context, encap_net_id, srv6_encap_network)
        encap_info = self._make_encap_rule_rpc_content(context, encap_net)
        self.sr_rpc_api.encap_rule_update(context, encap_info)
        return encap_net

    def delete_srv6_encap_network(self, context, encap_net_id):
        encap_net_db = self._get_srv6_encap_network(context,
                                                    encap_net_id)
        encap_net = self._make_srv6_encap_network_dict(encap_net_db,
                                                       [])
        super(SRv6EncapNetworkPlugin,
              self).delete_srv6_encap_network(
                  context, encap_net_id)
        encap_info = self._make_encap_rule_rpc_content(context, encap_net)
        self.sr_rpc_api.encap_rule_update(context, encap_info)
