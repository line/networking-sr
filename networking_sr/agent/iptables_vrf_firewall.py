# Copyright (c) 2018 Line Corporation
# All Rights Reserved.
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

from oslo_log import log as logging

from neutron.agent.linux import iptables_firewall

from networking_sr.common import config  # noqa

SG_CHAIN = 'sg-chain'
LOG = logging.getLogger(__name__)


class VrfBasedIptablesFirewallDriver(iptables_firewall.IptablesFirewallDriver):
    def prepare_port_filter(self, port):
        LOG.debug("Preparing device (%s) filter", port['device'])
        self._set_ports(port)
        # Accept communitation to DHCP server(VM -> DHCP Server)
        chain = 'INPUT'
        rule = '-p udp -m udp --sport 68 --dport 67 -j ACCEPT'
        self.iptables.ipv4['filter'].add_rule(chain, rule, wrap=True, top=True)
        # Accept packets from metadata server to VM
        chain = 'FORWARD'
        rule = '-s 169.254.169.254 -p tcp -m tcp --sport 80 -j ACCEPT'
        self.iptables.ipv4['filter'].add_rule(chain, rule, wrap=True, top=True)
        vrf = port["binding:profile"].get("vrf")
        if vrf:
            # Accept packets from VM to metadata server
            chain = 'INPUT'
            rule = ("-i %(vrf)s -d 169.254.169.254 -p tcp -m tcp --dport 80 "
                    "-j ACCEPT" % {'vrf': vrf})
            self.iptables.ipv4['filter'].add_rule(chain, rule, wrap=True,
                                                  top=True)
            # Drop all connections against Hypervisor except for above
            # allowed port like metadata(169.254.169.254), dhcp...
            chain = 'INPUT'
            rule = '-i %(vrf)s -j DROP' % {'vrf': vrf}
            self.iptables.ipv4['filter'].add_rule(chain, rule, wrap=True)
        self._setup_chains()
        return self.iptables.apply()

    def _get_br_device_name(self, port):
        return "qbr%s" % port['device'][3:]
