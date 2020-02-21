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

import netaddr
import os
import sys

from neutron_lib.agent import topics
from neutron_lib import constants
from neutron_lib import exceptions
from oslo_config import cfg
from oslo_log import log as logging
import oslo_messaging
from oslo_service import service
from oslo_utils import excutils
import pyroute2
from pyroute2.config.eventlet import eventlet_config

from neutron.agent.common import utils
from neutron.agent.linux import bridge_lib
from neutron.agent.linux import external_process
from neutron.agent.linux import ip_lib
from neutron.api.rpc.handlers import securitygroups_rpc as sg_rpc
from neutron.common import config as common_config
from neutron.common import profiler as setup_profiler
from neutron.plugins.ml2.drivers.agent import _agent_manager_base as amb
from neutron.privileged.agent.linux import ip_lib as privileged

from networking_sr.agent import rpc as sr_rpc
from networking_sr.common import config  # noqa
from networking_sr.ml2.agent import sr_agent_loop


eventlet_config()

LOG = logging.getLogger(__name__)

SR_AGENT_BINARY = 'neutron-sr-agent'
AGENT_TYPE_SR = 'SR agent'
EXTENSION_DRIVER_TYPE = 'sr'
INTERFACE_FS = "/sys/class/net/"
RESOURCE_ID_LENGTH = 11
VRF_TABLE_NAMBER_BASE = 1000


class SysctlCommandError(exceptions.NeutronException):
    message = "Sysctl command %(cmd)s failed."


class SrManager(amb.CommonAgentManagerBase):

    def __init__(self):
        super(SrManager, self).__init__()
        self.process_monitor = external_process.ProcessMonitor(
            cfg.CONF, resource_type="sr-agent")

        self.node_id = cfg.CONF.sr.segment_node_id
        if not self.node_id:
            LOG.error("Segment Node ID is not set in config.")
            sys.exit(1)

        self.gw_id = cfg.CONF.sr.segment_gw_id

        self._setup_system()
        self._setup_ipv6()

        # vrf_tables = {"vrf name": vrf_table_id}
        self.vrf_tables = {}

        # Check existing vrf
        # TODO(hichihara): Refactor the following codes
        #       Exteded privileged ip_lib should be created
        with pyroute2.IPDB() as ipdb:
            interfaces = ipdb.by_name.keys()

        vrfs = []
        for i in interfaces:
            if i[:3] == "vrf":
                vrfs.append(i)

        with pyroute2.IPRoute() as ip:
            for vrf in vrfs:
                try:
                    vrf_id = ip.link_lookup(ifname=vrf)[0]
                except IndexError:
                    privileged.NetworkInterfaceNotFound(device=vrf,
                                                        namespace=None)

                link = ip.link("get", index=vrf_id)[0]
                linkinfo = self._nlattr_get(link['attrs'], 'IFLA_LINKINFO')
                if not linkinfo:
                    LOG.error("Failed to cannot found attr "
                              "IFLA_LINKINFO from vrf interface")
                    sys.exit(1)
                info_data = self._nlattr_get(linkinfo["attrs"],
                                             "IFLA_INFO_DATA")
                if not info_data:
                    LOG.error("Failed to cannot found attr "
                              "IFLA_INFO_DATA from vrf interface")
                    sys.exit(1)
                vrf_table = self._nlattr_get(info_data["attrs"],
                                             "IFLA_VRF_TABLE")
                if not vrf_table:
                    LOG.error("Failed to cannot found attr "
                              "IFLA_VRF_TABLE from vrf interface")
                    sys.exit(1)

                self.vrf_tables[vrf] = vrf_table
                LOG.debug("Found existing vrf %(vrf)s with table id "
                          "%(table_id)d", {"vrf": vrf, "table_id": vrf_table})

        # TODO(hichihara): Replace this to a way which actually gets
        # current rules
        self.encap_info = []

    def _nlattr_get(self, attrs, key):
        # Search by key from attrs, if not found, return None
        for attr in attrs:
            if attr[0] == key:
                return attr[1]
        return None

    def _setup_system(self):
        # Make sure to allow ip forward
        cmd = ['net.ipv4.ip_forward=1']
        result = ip_lib.sysctl(cmd)
        if result == 1:
            LOG.error("Failed to enable net.ipv4.ip_forward=1.")
            sys.exit(1)
        # Make sure to allow tcp packet to pass though default vrf
        cmd = ['net.ipv4.tcp_l3mdev_accept=1']
        result = ip_lib.sysctl(cmd)
        if result == 1:
            LOG.error("Failed to enable net.ipv4.tcp_l3mdev_accept=1.")
            sys.exit(1)
        # Make sure to allow udp packet to pass though default vrf
        cmd = ['net.ipv4.udp_l3mdev_accept=1']
        result = ip_lib.sysctl(cmd)
        if result == 1:
            LOG.error("Failed to enable net.ipv4.udp_l3mdev_accept=1.")
            sys.exit(1)
        cmd = ['net.ipv6.conf.all.seg6_enabled=1']
        result = ip_lib.sysctl(cmd)
        if result == 1:
            LOG.error("Failed to enable net.ipv6.conf.all.seg6_enabled=1.")
            sys.exit(1)
        cmd = ['net.ipv6.conf.all.forwarding=1']
        result = ip_lib.sysctl(cmd)
        if result == 1:
            LOG.error("Failed to enable net.ipv6.conf.all.forwarding=1.")
            sys.exit(1)
        cmd = ['net.ipv4.conf.all.rp_filter=0']
        result = ip_lib.sysctl(cmd)
        if result == 1:
            LOG.error("Failed to enable net.ipv4.conf.all.rp_filter=0.")
            sys.exit(1)
        for interface in cfg.CONF.sr.srv6_interfaces:
            cmd = ['net.ipv4.conf.%s.rp_filter=0' % interface]
            result = ip_lib.sysctl(cmd)
            if result == 1:
                LOG.error("Failed to enable net.ipv4.conf.%s.rp_filter=0.",
                          interface)
                sys.exit(1)
        # Make sure to allow bridge to call iptables
        cmd = ['net.bridge.bridge-nf-call-iptables=1']
        result = ip_lib.sysctl(cmd)
        if result == 1:
            LOG.error("Failed to enable net.bridge.bridge-nf-call-iptables=1.")
            sys.exit(1)

    def _setup_ipv6(self):
        # Setup SRv6 configuration
        # TODO(hichihara): Refactor to use ip_lib instead of command execute
        cmd = ["ip", "-6", "rule", "add", "pref", "32765", "table", "local"]
        utils.execute(cmd, run_as_root=True,
                      check_exit_code=False)
        cmd = ["ip", "-6", "rule", "del", "pref", "0"]
        utils.execute(cmd, run_as_root=True,
                      check_exit_code=False)

    def _setup_interface_ip(self, ip, interface='lo'):
        """Sets up an IP address on the target interface

        Args:
            ip(String): ip address with cidr
            interface(String): network interface, 'lo' by default
        Return:
            None
        """
        dev = ip_lib.IPDevice(interface)
        dev.addr = ip_lib.IpAddrCommand(dev)
        existing_addreses = ip_lib.get_devices_with_ip(None, name=dev.name)
        existing_ips = [addr['cidr'] for addr in existing_addreses]
        if ip not in existing_ips:
            LOG.info("Adding %s to %s interface" % (ip, dev.name))
            dev.addr.add(cidr=ip)
        else:
            LOG.debug("%s interface already have %s ip" % (dev.name, ip))

    def get_agent_configurations(self):
        configurations = {}
        configurations['segment_node_id'] = self.node_id
        return configurations

    def get_agent_id(self):
        devices = ip_lib.IPWrapper().get_devices(True)
        if devices:
            mac = ip_lib.get_device_mac(devices[0].name)
            return 'sr%s' % mac.replace(":", "")
        else:
            LOG.error("Unable to obtain MAC address for unique ID. "
                      "Agent terminated!")
            sys.exit(1)

    def get_all_devices(self, with_ifindex=False):
        """Return all existing tap devices

        They are technically devices having name starting with
        constants.TAP_DEVICE_PREFIX

        Args:
            with_ifindex(bool): if True, return dict include device index,
                                if False, return set include just device name
        Return:
            if with_ifindex is True:
                devices_with_ifindex(dict): {"<device_name>": "<device index>"}
            if with_ifindex is False:
                devices(set<String>): set contains device name
        """
        devices = {} if with_ifindex else set()
        for device in os.listdir(INTERFACE_FS):
            if not device.startswith(constants.TAP_DEVICE_PREFIX):
                continue
            # Try to lookup interface index as well
            if with_ifindex:
                try:
                    with open(os.path.join(
                        INTERFACE_FS, device, 'ifindex'), 'r') as f:
                        devices[device] = int(f.read().strip())
                except (IOError, ValueError):
                    # if we faied to lookup, this device has been deleted
                    # after exec listdir, so we should not that device as
                    # current device
                    continue
            else:
                devices.add(device)

        return devices

    def get_all_encap_rules(self):
        return self.encap_info

    def get_devices_modified_timestamps(self, devices):
        return {}

    def get_extension_driver_type(self):
        return EXTENSION_DRIVER_TYPE

    def get_rpc_callbacks(self, context, agent, sg_agent):
        return SrRpcCallbacks(context, agent, sg_agent)

    def get_agent_api(self, **kwargs):
        pass

    def get_rpc_consumers(self):
        consumers = [[topics.PORT, topics.UPDATE],
                     [topics.NETWORK, topics.UPDATE],
                     [topics.SECURITY_GROUP, topics.UPDATE],
                     [sr_rpc.TOPICS_ENCAP, topics.DELETE],
                     [sr_rpc.TOPICS_ENCAP_RULE, topics.UPDATE],
                     [sr_rpc.TOPICS_ENCAP, topics.UPDATE],
                     [sr_rpc.TOPICS_VRF, topics.DELETE]]
        return consumers

    def plug_interface(self, vrf, device, device_details, ports, vrf_ip,
                       vrf_cidr):
        tap_device_name = device
        try:
            if not ip_lib.device_exists(tap_device_name):
                LOG.debug("Tap device: %s does not exist on "
                          "this host, skipped", tap_device_name)
                return False

            self.configure_tap(tap_device_name, device_details['mac_address'],
                               device_details['related_ips'], ports,
                               vrf, vrf_ip, vrf_cidr)

            LOG.debug("Finished to configure tap %s device", tap_device_name)
            return True
        except Exception:
            with excutils.save_and_reraise_exception() as ctx:
                if not ip_lib.device_exists(tap_device_name):
                    # the exception was likely a side effect of the tap device
                    # being removed during handling so we just return false
                    # like we would if it didn't exist to begin with.
                    ctx.reraise = False
                    return False

    def configure_tap(self, tap_device_name, vm_mac, related_ips,
                      ports, vrf, vrf_ip, vrf_cidr):
        """Configure tap device

        The traffic for vm's ip goes to tap device vm connected to.
        NB: 1 port could have multiple ip address. that's why
        related_ips is list including ip informations

        Args:
            tap_device_name(String): tap device name
            vm_mac(String): mac address VM use
            related_ips(list<dict>): [{'gw_ip': <gateway_ip>,
                                       'cidr': <cidr of subnet>,
                                       'vm_ip': <vm ip address>}]
        Return:
            None
        """
        tap_dev = ip_lib.IPDevice(tap_device_name)
        tap_dev.addr = IpAddrCommandAcceptArgs(tap_dev)
        for related_ip in related_ips:
            # Ensure veth
            qvb, qvr = self._get_veth_pair_names(tap_device_name[3:])
            qvr_dev = self._add_veth(qvb, qvr)
            # Create brdige
            br_name = "qbr%s" % tap_device_name[3:]
            self._ensure_bridge(br_name, [qvb, tap_dev.name])
            cidr = '/' + related_ip['cidr']
            # assign virtual gateway ip to qvr
            qvr_address = related_ip['gw_ip'] + cidr
            LOG.debug("Ensure %s having %s" % (qvr_dev.name, qvr_address))
            self._ensure_dev_having_ip(qvr_dev, qvr_address)
            # Ensure vrf exist
            vrf_table = self._ensure_vrf(vrf, vrf_ip, vrf_cidr)
            # assign qvr to vrf
            self._add_avr_to_vrf(vrf, qvr)
            # Configure SRv6
            self._set_srv6_rules(vrf, vrf_ip, ports)
            # add static route /32 to tap
            vm_ip_for_route = related_ip['vm_ip'] + '/' + '32'
            LOG.debug("Ensure root namespace having route %s via %s" % (
                vm_ip_for_route, qvr_dev.name))
            self._ensure_vm_route(qvr_dev, vm_ip_for_route, vrf_table)

        for kernel_opts in ("net.ipv4.conf.%s.proxy_arp=1",
                            "net.ipv4.neigh.%s.proxy_delay=0"):
            cmd = [kernel_opts % qvr]
            result = ip_lib.sysctl(cmd)
            if result == 1:
                raise SysctlCommandError(cmd=cmd)

    def _get_veth_pair_names(self, iface_id):
        return (("qvb%s" % iface_id), ("qvr%s" % iface_id))

    def _add_veth(self, qvb, qvr):
        ip = ip_lib.IPWrapper()
        try:
            qvb_dev, qvr_dev = ip.add_veth(qvb, qvr)
            qvb_dev.link.set_up()
            qvr_dev.link.set_up()
        except RuntimeError:
            qvr_dev = ip_lib.IPDevice(qvr)
        qvr_dev.addr = IpAddrCommandAcceptArgs(qvr_dev)
        return qvr_dev

    def _bridge_exists_and_ensure_up(self, bridge_name):
        """Check if the bridge exists and make sure it is up."""
        br = ip_lib.IPDevice(bridge_name)
        br.set_log_fail_as_error(False)
        try:
            # If the device doesn't exist this will throw a RuntimeError
            br.link.set_up()
        except RuntimeError:
            return False
        return True

    def _ensure_bridge(self, bridge_name, interfaces):
        """Create a bridge unless it already exists."""
        # _bridge_exists_and_ensure_up instead of device_exists is used here
        # because there are cases where the bridge exists but it's not UP,
        # for example:
        # 1) A greenthread was executing this function and had not yet executed
        # "ip link set bridge_name up" before eventlet switched to this
        # thread running the same function
        # 2) The Nova VIF driver was running concurrently and had just created
        #    the bridge, but had not yet put it UP
        if not self._bridge_exists_and_ensure_up(bridge_name):
            LOG.debug("Starting bridge %(bridge_name)s for subinterface "
                      "%(interfaces)s",
                      {'bridge_name': bridge_name, 'interfaces': interfaces})
            bridge_device = bridge_lib.BridgeDevice.addbr(bridge_name)
            if bridge_device.setfd(0):
                return
            if bridge_device.disable_stp():
                return
            if bridge_device.disable_ipv6():
                return
            if bridge_device.link.set_up():
                return
            LOG.debug("Done starting bridge %(bridge_name)s for "
                      "subinterface %(interfaces)s",
                      {'bridge_name': bridge_name, 'interfaces': interfaces})
        else:
            bridge_device = bridge_lib.BridgeDevice(bridge_name)

        # Check if the interface is part of the bridge
        for interface in interfaces:
            if not bridge_device.owns_interface(interface):
                try:
                    bridge_device.addif(interface)
                except Exception as e:
                    LOG.error(("Unable to add %(interface)s to %(bridge_name)s"
                               "! Exception: %(e)s"),
                              {'interface': interface,
                               'bridge_name': bridge_name,
                               'e': e})
                    # Try ip link set
                    cmd = ["ip", "link", "set", "dev", interface, "master",
                           bridge_name]
                    utils.execute(cmd, run_as_root=True,
                                  check_exit_code=False)
                    return
        return bridge_name

    def _ensure_dev_having_ip(self, target_dev, ip):
        """Ensure target device have ip

        Args:
            target_dev(ip_lib.IPDevice):
            ip(String): ip address with cidr
        Return:
            None
        """
        existing_addreses = ip_lib.get_devices_with_ip(None,
                                                       name=target_dev.name)
        existing_ips = [addr['cidr'] for addr in existing_addreses]
        LOG.debug("The existing address of dev %s are %s" % (target_dev.name,
                                                             existing_ips))
        if ip not in existing_ips:
            target_dev.addr.add(
                cidr=ip, additional_args=['noprefixroute', ])
        else:
            LOG.debug("%s already have ip %s" % (target_dev.name, ip))

    def _ensure_vrf(self, vrf, vrf_ip, cidr):
        """Ensure vrf interface

        return: vrf_table
        """
        if self.vrf_tables:
            vrf_table = max(list(self.vrf_tables.values())) + 1
        else:
            vrf_table = VRF_TABLE_NAMBER_BASE
        if vrf not in list(self.vrf_tables):
            privileged.create_interface(vrf, None, "vrf", vrf_table=vrf_table)
            privileged.set_link_attribute(vrf, None, state="up")

            LOG.debug("VRF %s is created" % vrf)
            self.vrf_tables[vrf] = vrf_table

            # TODO(hichihara): Refactor to use ip_lib instead of command
            ip = vrf_ip + '/' + cidr
            self._setup_interface_ip(ip, vrf)
            cmd = ["ip", "route", "replace", vrf_ip, "dev", vrf]
            utils.execute(cmd, run_as_root=True,
                          check_exit_code=False)
            vrf_sid = ("%(node_id)s:%(vrf_ip)s/128" % {"node_id": self.node_id,
                                                       "vrf_ip": vrf_ip})
            self._setup_interface_ip(vrf_sid, vrf)
            self._setup_interface_ip("169.254.169.254/32", vrf)
            # Create encap rules
            for encap_info in self.encap_info:
                if vrf == encap_info['vrf']:
                    self.add_encap_rules([encap_info], add_flag=False)
                    break
        else:
            vrf_table = self.vrf_tables[vrf]
        return vrf_table

    def _add_avr_to_vrf(self, vrf, qvr):
        vrf_idx = privileged.get_link_id(vrf, None)
        privileged.set_link_attribute(qvr, None, master=vrf_idx)

    def _set_srv6_rules(self, vrf, vrf_ip, ports):
        # Encap rules
        for port in ports:
            # TODO(hichihara): Configure multiple fixed_ips
            target_ip = port["ip"] + "/32"
            target_node_id = port["segment_node_id"]
            if target_node_id is None:
                continue
            # Ensure connection between VMs have same network(vrf)
            target_vrf = port["vrf"]
            if target_vrf != vrf:
                continue
            if target_node_id != self.node_id:
                # Create target_sid
                target_sid = ("%(node_id)s:%(vrf_ip)s" % {
                    "node_id": target_node_id,
                    "vrf_ip": vrf_ip})
                cmd = ["ip", "route", "replace", target_ip, "encap", "seg6",
                       "mode", "encap", "segs", target_sid, "dev", vrf,
                       "vrf", vrf]
                utils.execute(cmd, run_as_root=True,
                              check_exit_code=False)

        # Default route to network nodes
        if self.gw_id:
            target_sid = ("%(node_id)s:%(vrf_ip)s" % {
                "node_id": self.gw_id,
                "vrf_ip": vrf_ip})
            cmd = ["ip", "route", "replace", "0.0.0.0/0", "encap", "seg6",
                   "mode", "encap", "segs", target_sid, "dev", vrf, "vrf", vrf]
            utils.execute(cmd, run_as_root=True,
                          check_exit_code=False)

        # Decap rules
        # TODO(hichihara): Refactor to use ip_lib instead of command execute
        decap_sid = ("%(node_id)s:%(vrf_ip)s" % {"node_id": self.node_id,
                                                 "vrf_ip": vrf_ip})
        cmd = ["ip", "-6", "route", "replace", "local", decap_sid, "encap",
               "seg6local", "action", "End.DX4", "nh4", vrf_ip, "dev", vrf]
        utils.execute(cmd, run_as_root=True,
                      check_exit_code=False)

    def _ensure_vm_route(self, target_dev, vm_route, vrf_table):
        """Ensure root namespace on host have vm_route

        Args:
            target_dev(ip_lib.IPDevice):
            vm_route(String): ip address for this vm with /32
                              e.g. If vm's ip is 192.168.0.2/16,
                              vm_route should be 192.168.0.2/32
        Return:
            None
        """
        target_dev.route.add_route(cidr=vm_route, table=vrf_table)

    def _get_ip_version(self, cidr):
        """Check if cidr is ip version 4 or not by existence of :

        Args:
            cidr(String): ip address with cidr
        Return:
            version(Int): 4 or 6 depending on cidr
        """
        if ":" in cidr:
            return 6
        else:
            return 4

    def add_encap_rules(self, encap_rules, add_flag=True):
        for target in encap_rules:
            # Set srv6 rule on the vrf
            vrf = target['vrf']
            encap_info = None
            for encap in self.encap_info:
                if encap['id'] == target['id']:
                    encap_info = encap
                    break
            for rule in target['rules']:
                ip = rule['destination']
                target_sid = rule['nexthop']
                cmd = ["ip", "route", "replace", ip, "encap", "seg6", "mode",
                       "encap", "segs", target_sid, "dev", vrf, "vrf", vrf]
                utils.execute(cmd, run_as_root=True,
                              check_exit_code=False)
            if add_flag:
                if encap_info is not None:
                    encap_info['rules'] += target['rules']
                else:
                    self.encap_info.append(target)

    def remove_encap_rules(self, encap_rules):
        for target in encap_rules:
            # Remove srv6 rule on the vrf
            vrf = target['vrf']
            encap_info = None
            for encap in self.encap_info:
                if encap['id'] == target['id']:
                    encap_info = encap
                    break
            else:
                break
            for rule in target['rules']:
                ip = rule['destination']
                target_sid = rule['nexthop']
                cmd = ["ip", "route", "del", ip, "encap", "seg6", "mode",
                       "encap", "segs", target_sid, "dev", vrf, "vrf", vrf]
                utils.execute(cmd, run_as_root=True,
                              check_exit_code=False)
                encap_info['rules'].remove(rule)

    def setup_target_sr(self, updated_targets):
        for target in updated_targets:
            # if target node is same as local node_id,
            # we should not configure encap rule
            if target["segment_node_id"] == self.node_id:
                continue
            # Set srv6 rule on the vrf
            vrf = target["vrf"]
            vrf_ip = target["vrf_ip"]
            # Ensure vrf exist
            self._ensure_vrf(vrf, vrf_ip, target["cidr"])
            ip = target["ip"] + "/32"
            node_id = target["segment_node_id"]
            target_sid = ("%(node_id)s:%(vrf_ip)s" % {
                "node_id": node_id,
                "vrf_ip": vrf_ip})
            cmd = ["ip", "route", "replace", ip, "encap", "seg6", "mode",
                   "encap", "segs", target_sid, "dev", vrf, "vrf", vrf]
            utils.execute(cmd, run_as_root=True,
                          check_exit_code=False)

    def clear_target_sr(self, removed_targets):
        for target in removed_targets:
            # Remove srv6 rule on the vrf
            vrf = target["vrf"]
            vrf_ip = target["vrf_ip"]
            ip = target["ip"] + "/32"
            node_id = target["segment_node_id"]
            target_sid = ("%(node_id)s:%(vrf_ip)s" % {
                "node_id": node_id,
                "vrf_ip": vrf_ip})
            cmd = ["ip", "route", "del", ip, "encap", "seg6", "mode",
                   "encap", "segs", target_sid, "dev", vrf, "vrf", vrf]
            utils.execute(cmd, run_as_root=True,
                          check_exit_code=False)

    def remove_vrf(self, vrf):
        if self.vrf_tables.get(vrf):
            privileged.set_link_attribute(vrf, None, state="down")
            privileged.delete_interface(vrf, None)
            self.vrf_tables.pop(vrf)
            LOG.debug("Removed vrf %s", vrf)

    def get_tap_device_name(self, interface_id):
        """Get tap device name by interface_id.

        Normally tap device name is the "tap" + first RESOURCE_ID_LENGTH
        characters of port id

        Args:
            interface_id(String): port uuid
        Return:
            tap_device_name(String): tap device name on the based of port id
        """
        if not interface_id:
            LOG.warning("Invalid Interface ID, will lead to incorrect "
                        "tap device name")
        tap_device_name = constants.TAP_DEVICE_PREFIX + \
            interface_id[:RESOURCE_ID_LENGTH]
        return tap_device_name

    def ensure_port_admin_state(self, tap_name, admin_state_up):
        """Ensure the tap device is same status as admin_state_up

        Args:
            tap_name(String): tap device name
            admin_state_up(Bool): port admin status neutron maintain
        Return:
            None
        """
        LOG.debug("Setting admin_state_up to %s for device %s",
                  admin_state_up, tap_name)
        if admin_state_up:
            ip_lib.IPDevice(tap_name).link.set_up()
        else:
            ip_lib.IPDevice(tap_name).link.set_down()

    def _delete_bridge(self, bridge_name):
        bridge_device = bridge_lib.BridgeDevice(bridge_name)
        if bridge_device.exists():
            try:
                LOG.debug("Deleting bridge %s", bridge_name)
                if bridge_device.link.set_down():
                    return
                if bridge_device.delbr():
                    return
                LOG.debug("Done deleting bridge %s", bridge_name)
                return
            except RuntimeError:
                pass
        LOG.debug("Cannot delete bridge %s; it does not exist",
                  bridge_name)

    def delete_port(self, device):
        # Delete veth
        qvb, qvr = self._get_veth_pair_names(device[3:])
        ip = ip_lib.IPWrapper()
        try:
            ip.del_veth(qvb)
            LOG.debug("Delete veth pair %s %s", qvb, qvr)
        except RuntimeError:
            pass
        # Delete bridge
        br_name = "qbr%s" % device[3:]
        self._delete_bridge(br_name)

    def setup_arp_spoofing_protection(self, device, device_details):
        pass

    def delete_arp_spoofing_protection(self, devices):
        pass

    def delete_unreferenced_arp_protection(self, current_devices):
        pass


class SrRpcCallbacks(sg_rpc.SecurityGroupAgentRpcCallbackMixin,
                     amb.CommonAgentManagerRpcCallBackBase):
    # Set RPC API version to 1.0 by default.
    # history
    #   1.1 Support Security Group RPC
    #   1.3 Added param devices_to_update to security_groups_provider_updated
    #   1.4 Added support for network_update
    target = oslo_messaging.Target(version='1.4')

    def __init__(self, context, agent, sg_agent):
        super(SrRpcCallbacks, self).__init__(context, agent, sg_agent)
        self.removed_devices_encap = set()
        self.removed_ports = {}
        self.encap_info = []
        self.updated_devices_encap = set()
        self.updated_ports = {}
        self.removed_vrfs = set()

    def port_update(self, context, **kwargs):
        """RPC for port_update event

        This method will be called when port is updated in neutron server
        this method just add device_name associating updated port into
        updated_devices list and this device recognized as updated device in
        next iteration and if tap is in own host, plug_interaface method
        will be executed with that tap
        """
        port_id = kwargs['port']['id']
        device_name = self.agent.mgr.get_tap_device_name(port_id)
        # Put the device name in the updated_devices set.
        # Do not store port details, as if they're used for processing
        # notifications there is no guarantee the notifications are
        # processed in the same order as the relevant API requests.
        self.updated_devices.add(device_name)
        LOG.debug("port_update RPC received for port: %s", port_id)

    def encap_rule_update(self, context, **kwargs):
        encap_info = kwargs['encap_info']
        for encap in self.encap_info:
            if encap['id'] == encap_info['id']:
                self.encap_info.remove(encap)
                break
        self.encap_info.append(encap_info)
        LOG.debug("encap_update RPC received for encap rules: %s",
                  encap_info)

    def get_and_clear_updated_encaps(self):
        encap_info = self.encap_info
        self.encap_info = []
        return encap_info

    def encap_delete(self, context, **kwargs):
        port = kwargs['port']
        port_id = port['id']
        device_name = self.agent.mgr.get_tap_device_name(port_id)
        self.removed_devices_encap.add(device_name)
        self.removed_ports[device_name] = port
        LOG.debug("encap_delete RPC received for port: %s", port_id)

    def encap_update(self, context, **kwargs):
        port = kwargs['port']
        port_id = port['id']
        device_name = self.agent.mgr.get_tap_device_name(port_id)

        self.updated_devices_encap.add(device_name)
        self.updated_ports[device_name] = port
        LOG.debug("encap_update RPC received for port: %s", port_id)

    def network_update(self, context, **kwargs):
        """RPC for network_update event

        This method will be called when network is updated in neutron server
        this method add all ports under this network into updated_devices list
        """
        network_id = kwargs['network']['id']
        LOG.debug("network_update message processed for network "
                  "%(network_id)s, with ports: %(ports)s",
                  {'network_id': network_id,
                   'ports': self.agent.network_ports[network_id]})
        for port_data in self.agent.network_ports[network_id]:
            self.updated_devices.add(port_data['device'])

    def get_and_clear_removed_devices_encap(self):
        """Get and clear the list of devices for which a removed was received.

        :return: set - A set with removed devices. Format is ['tap1', 'tap2']
        """

        # Save and reinitialize the set variable that the port_delete RPC uses.
        # This should be thread-safe as the greenthread should not yield
        # between these two statements.
        removed_devices_encap = self.removed_devices_encap
        self.removed_devices_encap = set()
        return removed_devices_encap

    def get_removed_ports(self, devices):
        for device in devices:
            try:
                yield self.removed_ports[device]
            except KeyError:
                # Already removed
                pass

    def clear_removed_ports(self, devices):
        for device in devices:
            self.removed_ports.pop(device, None)

    def network_delete(self, context, **kwargs):
        pass

    def get_and_clear_updated_devices_encap(self):
        """Get and clear the list of devices for which a updated was received.

        :return: set - A set with updated devices. Format is ['tap1', 'tap2']
        """

        # Save and reinitialize the set variable that the port_delete RPC uses.
        # This should be thread-safe as the greenthread should not yield
        # between these two statements.
        updated_devices_encap = self.updated_devices_encap
        self.updated_devices_encap = set()
        return updated_devices_encap

    def get_updated_ports(self, devices):
        for device in devices:
            try:
                yield self.updated_ports[device]
            except KeyError:
                # Already removed
                pass

    def clear_updated_ports(self, devices):
        for device in devices:
            self.updated_ports.pop(device, None)

    def vrf_delete(self, context, **kwargs):
        vrf = kwargs['vrf']
        LOG.debug("vrf_delete message processed for vrf "
                  "%(vrf)s", {'vrf': vrf})
        self.removed_vrfs.add(vrf)

    def get_and_clear_removed_vrfs(self):
        """Get and clear the list of vrfs for which a removed was received.

        :return: set - A set with removed vrfs.
        """
        removed_vrfs = self.removed_vrfs
        self.removed_vrfs = set()
        return removed_vrfs


class IpAddrCommandAcceptArgs(ip_lib.IpAddrCommand):

    def add(self, cidr, scope='global', add_broadcast=True,
            additional_args=None):
        """This is method for executing "ip addr add" as root

        The reason why it override is we want to specify option.
        but super class doesn't allow us to pass additional option

        Args:
            cidr(String): ip address with subnet
            scope(String): scope of this address
            add_broadcast(Bool): if True, it add "brd" option
            additional_args(list<String>): additional arguments
        Return:
            None
        """
        net = netaddr.IPNetwork(cidr)
        args = ['add', cidr,
                'scope', scope,
                'dev', self.name]
        if add_broadcast and net.version == 4:
            args += ['brd', str(net[-1])]
        if additional_args:
            args += additional_args
        self._as_root([net.version], tuple(args))


def main():
    common_config.init(sys.argv[1:])
    common_config.setup_logging()

    manager = SrManager()

    polling_interval = cfg.CONF.AGENT.polling_interval
    quitting_rpc_timeout = cfg.CONF.AGENT.quitting_rpc_timeout
    agent = sr_agent_loop.SrAgentLoop(manager, polling_interval,
                                      quitting_rpc_timeout,
                                      AGENT_TYPE_SR,
                                      SR_AGENT_BINARY)
    setup_profiler.setup(SR_AGENT_BINARY, cfg.CONF.host)
    LOG.info("Agent initialized successfully, now running... ")
    launcher = service.launch(cfg.CONF, agent, restart_method='mutate')
    launcher.wait()
