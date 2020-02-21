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

from oslo_config import cfg

from neutron._i18n import _

SR_MODE_V6 = "srv6"

sr_opts = [
    cfg.StrOpt('sr_mode', default=SR_MODE_V6,
               help=_("Segment Routing mode.")),
    cfg.StrOpt('segment_node_id',
               help=_("Segment Node ID of host")),
    cfg.StrOpt('segment_gw_id',
               help=_("Segment Node ID of network nodes so that VMs can "
                      "access out of SRv6 network. The SID is set as default "
                      "route on VRF")),
    cfg.ListOpt('srv6_interfaces', default=[],
                help=_("Interfaces are set SRv6 rules. Agent sets "
                       "rp_filter=0 to them")),
]


cfg.CONF.register_opts(sr_opts, "sr")
