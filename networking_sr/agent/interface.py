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
from oslo_log import log as logging

from neutron.agent.linux import interface as n_interface
from neutron.agent.linux import ip_lib

LOG = logging.getLogger(__name__)


class SrInterfaceDriver(n_interface.LinuxInterfaceDriver):

    DEV_NAME_PREFIX = 'ns-'

    def plug_new(self, network_id, port_id, device_name, mac_address,
                 bridge=None, namespace=None, prefix=None, mtu=None):
        """Plugin the interface."""
        ip = ip_lib.IPWrapper()

        # Enable agent to define the prefix
        tap_name = device_name.replace(prefix or self.DEV_NAME_PREFIX,
                                       constants.TAP_DEVICE_PREFIX)
        # Create ns_veth in a namespace if one is configured.
        root_veth, ns_veth = ip.add_veth(tap_name, device_name,
                                         namespace2=namespace)
        root_veth.disable_ipv6()
        ns_veth.link.set_address(mac_address)

        if mtu:
            self.set_mtu(device_name, mtu, namespace=namespace, prefix=prefix)
        else:
            LOG.warning("No MTU configured for port %s", port_id)

        root_veth.link.set_up()
        ns_veth.link.set_up()

    def unplug(self, device_name, bridge=None, namespace=None, prefix=None):
        """Unplug the interface."""
        device = ip_lib.IPDevice(device_name, namespace=namespace)
        try:
            device.link.delete()
            LOG.debug("Unplugged interface '%s'", device_name)
        except RuntimeError:
            LOG.error("Failed unplugging interface '%s'",
                      device_name)

    def set_mtu(self, device_name, mtu, namespace=None, prefix=None):
        tap_name = device_name.replace(prefix or self.DEV_NAME_PREFIX,
                                       constants.TAP_DEVICE_PREFIX)
        root_dev, ns_dev = n_interface._get_veth(
            tap_name, device_name, namespace2=namespace)
        root_dev.link.set_mtu(mtu)
        ns_dev.link.set_mtu(mtu)
