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

from functools import partial
import time

from neutron_lib.agent import topics
from neutron_lib.utils import helpers
from oslo_config import cfg
from oslo_log import log as logging
from oslo_service import loopingcall

from neutron.agent.dhcp.agent import DhcpPluginApi
from neutron.agent.metadata.agent import MetadataPluginAPI
from neutron.api.rpc.handlers import resources_rpc
from neutron.plugins.ml2.drivers.agent import _common_agent as ca

from networking_sr.common import vrf_utils
from networking_sr.ml2.agent.dnsmasq_manager import DnsmasqManager
from networking_sr.objects import srv6_encap_network as objects

LOG = logging.getLogger(__name__)


class SrAgentLoop(ca.CommonAgentLoop):

    def setup_rpc(self):
        """Setup some rpc mechanisms

        This method try to initialise all rpc client this agent loop
        need to use. in addition to rpc client common agent loop is using,
        We setp dhcp_rpc in order to get subnet information
        Args:
            None
        Return:
            None
        """

        self.dhcp_rpc = DhcpPluginApi(topics.PLUGIN, cfg.CONF.host)
        self.meta_rpc = MetadataPluginAPI(topics.PLUGIN)
        self.resource_rpc = resources_rpc.ResourcesPullRpcApi()
        super(SrAgentLoop, self).setup_rpc()

    def start(self):
        """Start agent

        This is the entry point for sr agent, Once sr agent
        command is executed, this method will be called by oslo_service
        Args:
            None
        Return:
            None
        """
        self.subnet_info_map = {}
        self.force_updated_device = []
        # network_info_map = {'network_id': 'provider:network_type'}
        self.network_type_map = {}
        # NOTE: Unnecessary for nova-meta-api model
        # MetadataProxyManager.initialize(self.mgr.process_monitor)
        DnsmasqManager.initialize(self.mgr.process_monitor)

        sync_host_func = partial(DnsmasqManager.sync_host_entries,
                                 self.mgr.get_all_devices,
                                 self.add_force_updated_device)

        sync_host_service = loopingcall.FixedIntervalLoopingCall(
            sync_host_func)
        # NOTE: Use static value instead of config
        sync_host_service.start(
            interval=60)

        super(SrAgentLoop, self).start()

    def add_force_updated_device(self, device):
        """Add device(interface name) into force_updated_device

        This list contains device name that have to be reconfigured.
        Args:
            device(String): device name usually tapXXXXX
        Return:
            None
        """
        self.force_updated_device.append(device)
        LOG.warning("Added %s into force_updated_device list", device)

    def get_force_updated_device_and_clear(self):
        """Get force_updated_device list and clear that list

        Args:
            None
        Return:
            devices(list<String>): list contains device name have to be
                                   configured
        """
        devices = self.force_updated_device
        self.force_updated_device = []
        return devices

    def _get_ifindex_changed(self, previous, current):
        """Get interface index changed

        Compare interface index map between previous and current and
        return set including device name only having different interface
        index than previous one.
        Args:
            previous(dict): {"<device_name>": "<device index>"}
            current(dict):  {"<device_name>": "<device index>"}
        Return:
            changed_device_names(set<String>) :
                         set inlcuding device name having different
                         index than previous interface index map
        """
        changed_device_names = set()
        for c_dev_name, c_dev_i in current.items():
            if previous.get(c_dev_name) and\
                    c_dev_i != previous.get(c_dev_name):
                changed_device_names.add(c_dev_name)
        return changed_device_names

    def scan_devices(self, previous, sync):
        """Scan devices and check which tap device is new/changed/removed

        Args:
            previous(dict): previous device information
                           {"added": set<String>,
                            "current": set<String>,
                            "updated": set<String>,
                            "removed": set<String>,
                            "ifmap": {"<device_name>": "<device index>"}
                           }
            sync(Bool): If this is true, we believe all current devices as new
        Return:
            device_info(dict): same format as previous(dict)
        """
        device_info = {}
        updated_devices = self.rpc_callbacks.get_and_clear_updated_devices()

        current_devices_ifindex = self.mgr.get_all_devices(with_ifindex=True)
        current_devices = set(current_devices_ifindex.keys())
        device_info['current'] = current_devices

        if previous is None:
            # NOTE: In rocky, ifmap is changed to timestamps but not affect
            previous = {'added': set(), 'current': set(),
                        'updated': set(), 'removed': set(), 'ifmap': {}}

        device_info['ifmap'] = current_devices_ifindex
        locally_updated = self._get_ifindex_changed(previous['ifmap'],
                                                    device_info['ifmap'])
        locally_updated |= set(self.get_force_updated_device_and_clear())

        if locally_updated:
            LOG.debug("Adding locally changed devices to updated set: %s",
                      locally_updated)
            updated_devices |= locally_updated

        if sync:
            LOG.info("Sync all devices")
            # This is the first iteration, or the previous one had a problem.
            # Re-add all existing devices.
            device_info['added'] = current_devices

            # Retry cleaning devices that may not have been cleaned properly.
            # And clean any that disappeared since the previous iteration.
            device_info['removed'] = (previous['removed'] |
                                      previous['current'] -
                                      current_devices)

            # Retry updating devices that may not have been updated properly.
            # And any that were updated since the previous iteration.
            # Only update devices that currently exist.
            device_info['updated'] = (previous['updated'] |
                                      updated_devices &
                                      current_devices)

        else:
            device_info['added'] = current_devices - previous['current']
            device_info['removed'] = previous['current'] - current_devices
            device_info['updated'] = updated_devices & current_devices

        return device_info

    def scan_encaps(self, previous, sync):
        """Scan encap rules and check which rules is new/changed/removed

        Args:
            previous(dict): previous encap information
                           {"targets": list
                            "targets_updated": list
                            "targets_removed": list
                           }
            sync(Bool): If this is true, all current encap rules as new
        Return:
            encap_info(dict): same format as previous(dict)
        """
        encap_info = {'targets': [], 'targets_updated': [],
                      'targets_removed': []}

        updated_encaps = self.rpc_callbacks.get_and_clear_updated_encaps()
        all_encaps = self.mgr.get_all_encap_rules()

        if previous is None:
            previous = {'targets': [], 'targets_updated': [],
                        'targets_removed': []}

        if sync:
            LOG.info("Sync all encap rules")
            encap_nets = self.resource_rpc.bulk_pull(
                self.context,
                objects.SRv6EncapNetwork.obj_name())
            # NOTE: Fails to get encap_nets.encap_rules so gets encap_rules
            bulk_encap_rules = self.resource_rpc.bulk_pull(
                self.context,
                objects.SRv6EncapRule.obj_name())
            current_encaps = []
            for encap_net in encap_nets:
                net_id = encap_net['network_id']
                project_id = encap_net['project_id']
                network_type = self.network_type_map.get(net_id)
                if network_type is None:
                    network_info = self.dhcp_rpc.get_network_info(net_id)
                    network_type = network_info["provider:network_type"]
                    self.network_type_map[net_id] = network_type
                vrf = vrf_utils.get_vrf_name(network_type, project_id, net_id)
                encap_rules = []
                for rule in bulk_encap_rules:
                    if rule.srv6_encap_network_id != encap_net['id']:
                        continue
                    encap_rules.append({"destination": rule['destination'],
                                        "nexthop": rule['nexthop']})
                current_encaps.append({'id': encap_net['id'],
                                       'rules': encap_rules,
                                       'vrf': vrf})
            for encap in current_encaps:
                for pre_encap in all_encaps:
                    if encap['id'] == pre_encap['id']:
                        added, removed = helpers.diff_list_of_dict(
                            pre_encap['rules'],
                            encap['rules'])
                        encap_info['targets_updated'].append(
                            {'id': encap['id'],
                             'rules': added,
                             'vrf': encap['vrf']})
                        encap_info['targets_removed'].append(
                            {'id': encap['id'],
                             'rules': removed,
                             'vrf': encap['vrf']})
                        break
                else:
                    encap_info['targets_updated'].append(
                        {'id': encap['id'],
                         'rules': encap['rules'],
                         'vrf': encap['vrf']})
            encap_info['targets'] = current_encaps
        else:
            for encap in updated_encaps:
                for pre_encap in previous['targets']:
                    if encap['id'] == pre_encap['id']:
                        added, removed = helpers.diff_list_of_dict(
                            pre_encap['rules'],
                            encap['rules'])
                        encap_info['targets_updated'].append(
                            {'id': encap['id'],
                             'rules': added,
                             'vrf': encap['vrf']})
                        encap_info['targets_removed'].append(
                            {'id': encap['id'],
                             'rules': removed,
                             'vrf': encap['vrf']})
                        if (len(removed) != len(pre_encap['rules'])) or added:
                            encap_info['targets'].append(encap)
                        previous['targets'].remove(pre_encap)
                        break
                else:
                    encap_info['targets_updated'].append(
                        {'id': encap['id'],
                         'rules': encap['rules'],
                         'vrf': encap['vrf']})
                    encap_info['targets'].append(encap)
            encap_info['targets'] += previous['targets']
        return encap_info

    def scan_devices_encap(self, previous, sync):
        """Scan encap of devices and check which port is new/changed/removed

        Args:
            previous(dict): previous device encap information
                           {"targets": set<String>
                            "targets_updated": set<String>
                            "targets_removed": set<String>
                           }
            sync(Bool): If this is true, we believe all current devices as new
        Return:
            device_encap_info(dict): same format as previous(dict)
        """
        device_encap_info = {}
        updated_devices_encap = \
            self.rpc_callbacks.get_and_clear_updated_devices_encap()
        removed_devices_encap = \
            self.rpc_callbacks.get_and_clear_removed_devices_encap()
        current_devices_ifindex = self.mgr.get_all_devices(with_ifindex=True)
        current_devices = set(current_devices_ifindex.keys())
        # Removes device info isn't included in targets_updated
        self.rpc_callbacks.clear_updated_ports(current_devices)

        if previous is None:
            # NOTE: In rocky, ifmap is changed to timestamps but not affect
            previous = {'targets': set(), 'targets_updated': set(),
                        'targets_removed': set()}
        if sync:
            LOG.info("Sync all devices encap rules")
            device_encap_info['targets_updated'] = (
                updated_devices_encap - current_devices
            ) | previous["targets"]
            # Take care of a case device stored in both updated and removed
            device_encap_info['targets_updated'] -= removed_devices_encap
            device_encap_info['targets_removed'] = (
                removed_devices_encap | previous["targets_removed"])
            device_encap_info['targets'] = (
                device_encap_info['targets_updated'] -
                device_encap_info['targets_removed'])
        else:
            # Doesn't detect existing port update for SR
            device_encap_info['targets_updated'] = (
                updated_devices_encap - current_devices)
            # Take care of a case device stored in both updated and removed
            device_encap_info['targets_updated'] -= removed_devices_encap
            device_encap_info['targets_removed'] = removed_devices_encap
            device_encap_info['targets'] = (
                previous['targets'] | device_encap_info['targets_updated']
            ) - device_encap_info['targets_removed']
        return device_encap_info

    def scan_removed_vrfs(self, previous, sync):
        """Scan removed vrfs

        Args:
            previous(set): List of previous removed vrfs
            sync(Bool): If this is true, all removed vrfs as new
        Return:
            removed_vrf_info(set): List of removed vrfs
        """
        removed_vrf_info = set()
        removed_vrfs = self.rpc_callbacks.get_and_clear_removed_vrfs()

        if previous is None:
            previous = set()

        if sync:
            LOG.info("Sync all removed vrfs")
            removed_vrf_info = removed_vrfs | previous
        else:
            removed_vrf_info = removed_vrfs
            return removed_vrf_info

    def process_sr_devices(self, device_info):
        resync_a = False
        resync_b = False

        if device_info.get('targets_updated'):
            resync_a = self.treat_sr_devices_updated(
                device_info['targets_updated'])

        if device_info.get('targets_removed'):
            resync_b = self.treat_sr_devices_removed(
                device_info['targets_removed'])
        # If one of the above operations fails => resync with plugin
        return (resync_a | resync_b)

    def process_encap_rules(self, encap_info):
        resync_a = False
        resync_b = False

        if encap_info.get('targets_removed'):
            resync_a = self.treat_encap_rules_removed(
                encap_info['targets_removed'])

        if encap_info.get('targets_updated'):
            resync_b = self.treat_encap_rules_updated(
                encap_info['targets_updated'])

        # If one of the above operations fails => resync with plugin
        return (resync_a | resync_b)

    def treat_sr_devices_updated(self, devices):
        updated_targets = []
        for port in self.rpc_callbacks.get_updated_ports(devices):
            target_node_id = port["binding:profile"].get("segment_node_id")
            target_vrf = port["binding:profile"].get("vrf")
            target_vrf_ip = port["binding:profile"].get("vrf_ip")
            target_vrf_cidr = port["binding:profile"].get("vrf_cidr")
            if not target_node_id or not target_vrf:
                LOG.error("Detected a port without SRv6 info")
                return True
            for fixed_ip in port["fixed_ips"]:
                ip = fixed_ip['ip_address']
                cidr = target_vrf_cidr.split('/')[-1]
                updated_targets.append({
                    "ip": ip,
                    "vrf": target_vrf,
                    "cidr": cidr,
                    "segment_node_id": target_node_id,
                    "vrf_ip": target_vrf_ip
                })
        if updated_targets:
            self.mgr.setup_target_sr(updated_targets)
            self.rpc_callbacks.clear_updated_ports(devices)
        return False

    def treat_sr_devices_removed(self, devices):
        removed_targets = []
        for port in self.rpc_callbacks.get_removed_ports(devices):
            target_node_id = port["binding:profile"].get("segment_node_id")
            target_vrf = port["binding:profile"].get("vrf")
            target_vrf_ip = port["binding:profile"].get("vrf_ip")
            if not target_node_id or not target_vrf:
                continue
            for fixed_ip in port["fixed_ips"]:
                ip = fixed_ip['ip_address']
                removed_targets.append({
                    "ip": ip,
                    "vrf": target_vrf,
                    "cidr": "",
                    "segment_node_id": target_node_id,
                    "vrf_ip": target_vrf_ip
                })
        if removed_targets:
            self.mgr.clear_target_sr(removed_targets)
            self.rpc_callbacks.clear_removed_ports(devices)
        return False

    def treat_encap_rules_updated(self, encap_rules):
        self.mgr.add_encap_rules(encap_rules)
        return False

    def treat_encap_rules_removed(self, encap_rules):
        self.mgr.remove_encap_rules(encap_rules)
        return False

    def treat_vrf_remove(self, removed_vrf_info):
        for vrf in removed_vrf_info:
            self.mgr.remove_vrf(vrf)
        return False

    def _device_info_has_changes(self, device_info):
        return (device_info.get('added') or
                device_info.get('updated') or
                device_info.get('removed'))

    def _device_sr_info_has_changes(self, device_info):
        return (device_info.get('targets_updated') or
                device_info.get('targets_removed'))

    def _encap_rule_info_has_changes(self, encap_info):
        return (encap_info.get('targets_updated') or
                encap_info.get('targets_removed'))

    def daemon_loop(self):
        LOG.info("%s Agent RPC Daemon Started!", self.agent_type)
        device_info = None
        encap_info = None
        device_encap_info = None
        removed_vrf_info = None
        sync = True

        while True:
            start = time.time()

            if self.fullsync:
                sync = True
                self.fullsync = False

            if sync:
                LOG.info("%s Agent out of sync with plugin!",
                         self.agent_type)

            device_info = self.scan_devices(previous=device_info, sync=sync)
            encap_info = self.scan_encaps(previous=encap_info, sync=sync)
            device_encap_info = self.scan_devices_encap(
                previous=device_encap_info,
                sync=sync)
            removed_vrf_info = self.scan_removed_vrfs(
                previous=removed_vrf_info,
                sync=sync)
            sync = False

            if (self._device_info_has_changes(device_info) or
                    self.sg_agent.firewall_refresh_needed()):
                LOG.debug("Agent loop found changes! %s", device_info)
                try:
                    sync = self.process_network_devices(device_info)
                except Exception:
                    LOG.exception("Error in agent loop. Devices info: %s",
                                  device_info)
                    sync = True

            if self._device_sr_info_has_changes(device_encap_info):
                LOG.debug("Agent loop found SR changes! %s", device_encap_info)
                try:
                    sync = self.process_sr_devices(device_encap_info)
                except Exception:
                    LOG.exception("Error in agent loop. SR Devices info: %s",
                                  device_encap_info)
                    sync = True

            if self._encap_rule_info_has_changes(encap_info):
                LOG.debug("Agent loop found Encap Rule changes! %s",
                          encap_info)
                try:
                    sync = self.process_encap_rules(encap_info)
                except Exception:
                    LOG.exception("Error in agent loop. Encap Rules info: %s",
                                  encap_info)
                    sync = True

            if removed_vrf_info:
                LOG.debug("Agent loop found vrfs should be removed! %s",
                          removed_vrf_info)
                try:
                    sync = self.treat_vrf_remove(removed_vrf_info)
                except Exception:
                    LOG.exception("Error in agent loop. Removed vrf info: "
                                  "%s", removed_vrf_info)
                    sync = True

            # sleep till end of polling interval
            elapsed = (time.time() - start)
            if (elapsed < self.polling_interval):
                time.sleep(self.polling_interval - elapsed)
            else:
                LOG.debug("Loop iteration exceeded interval "
                          "(%(polling_interval)s vs. %(elapsed)s)!",
                          {'polling_interval': self.polling_interval,
                           'elapsed': elapsed})

    def _lookup_subnet_info(self, subnet_id, network_id):
        """Get subnet information

        At first this try to search local cache(self.subnet_info_map) but if
        there is no cache, it try to call rpc api to get subnet information
        matching subnet_id from neutron server and update subnet cache

        Args:
            subnet_id(String): subnet uuid
            network_id(String): network uuid
        Return:
            subnet_info(dict): {"gateway_ip": <gateway_ip>,
                                "cidr": <nw_address/cidr notation>,
                                "allocation_pools": [{"start": <ip_address>,
                                                      "end": <ip_address>},],
                                "host_routes": [{"destination": <cidr>,
                                                 "next_hop": <ip_address>}]
                                }
        """
        if subnet_id not in self.subnet_info_map:
            LOG.debug("Subnet %s is not in subnet_info_map,"
                      " retrieving its details via RPC", subnet_id)
            try:
                network_info = self.dhcp_rpc.get_network_info(network_id)
                LOG.debug("get_network_info rpc returned %s" % network_info)
                for subnet in network_info["subnets"]:
                    self.subnet_info_map[subnet["id"]] = {
                        "gateway_ip": subnet["gateway_ip"],
                        "cidr": subnet["cidr"],
                        "allocation_pools": subnet["allocation_pools"],
                        "host_routes": subnet["host_routes"],
                        "dns_nameservers": subnet.get("dns_nameservers", [])
                    }
            except Exception as e:
                LOG.exception(
                    "Unable to get subnet information for %s from %s"
                    " network: %s", subnet_id, network_id, e)
                return {}
        return self.subnet_info_map[subnet_id]

    def _translate_routes_format(self, host_routes):
        """Translate the format from neutron defined to dnsmasq friendly format

        Args:
            host_routes(list<dict>): [{"destination": <cidr>,
                                       "next_hop": <ip_address>}]
        Return:
            static_routes(list): ["<cidr>,<gateway_ip>",]
        """
        static_routes = []
        for host_route in host_routes:
            static_routes.append(
                host_route["destination"] + "," + host_route["nexthop"])
        return static_routes

    # This will be called when "new tap device being appeared" or
    # "port updated on server side and updated port related device is on host"
    # regardless of binding status
    def treat_devices_added_updated(self, devices):
        """Treat devices addedd or updated

        This method will be called when new/updated tap deivces detected.
        The reason why we override this method is we want to pass more
        information about port onto manager rather than just segment id,
        network type, device owner.
        Args:
            devices(list<String>): list contains device name such as tapXXX
        Return:
            resync_flg(Bool): If it's True, try to full sync in next interation
        """
        try:
            # This doesn't return the ports matching following conditions
            #  * port not existing in neutron database
            #  * port exisiting but being not bound to anywhere
            # In other words, this rpc call return following ports
            #  * port being bound to other host
            #  * port beind bound to own host

            # NOTE: I cannot understand the reason doesn't specify host
            """
            devices_details_list = self.plugin_rpc.get_devices_details_list(
                self.context, devices, self.agent_id)
            """
            devices_details_list = self.plugin_rpc.get_devices_details_list(
                self.context, devices, self.agent_id, host=cfg.CONF.host)
            # If we don't specify host here and call above rpc api with the
            # port bound to somewhere else than myself, Neutron server change
            # port status to BUILD inside rpc api.
            # One more thing we have to notice here this rpc call still return
            # port even if that is bound to other host without host
            # information, which measn there is no way for agent to know
            # if we have to bind that tap into own or not by just this rpc
        except Exception:
            LOG.exception("Unable to get port details for %s", devices)
            # resync is needed
            return True

        for device_details in devices_details_list:
            device = device_details['device']
            LOG.debug("Port %s adding", device)
            if 'port_id' in device_details:
                LOG.info("Port %(device)s details: %(details)s",
                         {'device': device, 'details': device_details})
                network_id = device_details['network_id']
                vrf = device_details["profile"].get("vrf")
                vrf_ip = device_details["profile"].get("vrf_ip")
                vrf_cidr = device_details["profile"].get("vrf_cidr")
                if vrf_cidr:
                    cidr = vrf_cidr.split('/')[-1]
                if vrf is None:
                    return True
                related_ips = []
                for fixed_ip in device_details['fixed_ips']:
                    subnet_id = fixed_ip['subnet_id']
                    vm_ip = fixed_ip['ip_address']
                    subnet_info = self._lookup_subnet_info(subnet_id,
                                                           network_id)
                    if subnet_info:
                        cidr_notation = subnet_info['cidr'].split('/')[-1]
                        related_ips.append({
                            "vm_ip": vm_ip,
                            "gw_ip": subnet_info['gateway_ip'],
                            "cidr": cidr_notation
                        })
                        created = DnsmasqManager.ensure_dhcp_opts(
                            subnet_id,
                            self.subnet_info_map[subnet_id]["gateway_ip"],
                            self._translate_routes_format(
                                self.subnet_info_map[
                                    subnet_id]["host_routes"]),
                            cidr_notation,
                            self.subnet_info_map[subnet_id]["dns_nameservers"])
                        if not created:
                            return True

                        created = DnsmasqManager.add_fixedip_entry(
                            subnet_id, device,
                            device_details["mac_address"], vm_ip)
                        if not created:
                            return True
                    else:
                        # resync is needed
                        return True

                device_details['related_ips'] = related_ips

                # Get ports info of VMs which belogn on the same project
                # and network
                port_id = device_details['port_id']
                ports = self.meta_rpc.get_ports(
                    self.context, filters={'id': [port_id]})
                project_id = ports[0]['project_id']
                ports = self.meta_rpc.get_ports(
                    self.context, filters={'network_id': [network_id],
                                           'project_id': [project_id]})
                target_ports = []
                for port in ports:
                    target_node_id = port["binding:profile"].get(
                        "segment_node_id")
                    if (cfg.CONF.sr.segment_node_id == target_node_id or
                            port['id'] == port_id):
                        continue
                    target_vrf = port["binding:profile"].get("vrf")
                    target_vrf_ip = port["binding:profile"].get("vrf_ip")
                    target_vrf_cidr = port["binding:profile"].get("vrf_cidr")
                    if not target_node_id or not target_vrf:
                        continue
                    for fixed_ip in port["fixed_ips"]:
                        target_ip = fixed_ip['ip_address']
                        target_cidr = target_vrf_cidr.split('/')[-1]
                        target_ports.append({
                            "ip": target_ip,
                            "vrf": target_vrf,
                            "cidr": target_cidr,
                            "segment_node_id": target_node_id,
                            "vrf_ip": target_vrf_ip
                        })
                interface_plugged = self.mgr.plug_interface(
                    vrf, device, device_details, target_ports, vrf_ip,
                    cidr)

                if interface_plugged:
                    self.mgr.ensure_port_admin_state(
                        device, device_details['admin_state_up'])
                # update plugin about port status if admin_state is up
                if device_details['admin_state_up']:
                    if interface_plugged:
                        # NB: We have to call this rpc to let neutron server
                        # know we could plug new tap device into our network
                        # even if new tap is not bound to own host, because
                        # Nova intentionally try to plug tap into other host
                        # than bounded host neutron know when just before
                        # start live migration for Nova to know if destination
                        # host can plug tap device or not But some packet loss
                        # could happen at that time, cause we will configure
                        # static route for that tap
                        self.plugin_rpc.update_device_up(self.context,
                                                         device,
                                                         self.agent_id,
                                                         cfg.CONF.host)
                    else:
                        self.plugin_rpc.update_device_down(self.context,
                                                           device,
                                                           self.agent_id,
                                                           cfg.CONF.host)
                self._update_network_ports(device_details['network_id'],
                                           device_details['port_id'],
                                           device_details['device'])
                self.ext_manager.handle_port(self.context, device_details)
            else:
                LOG.info("Device %s not defined on plugin", device)
        # no resync is needed
        return False

    def treat_devices_removed(self, devices):
        resync = False
        self.sg_agent.remove_devices_filter(devices)
        for device in devices:
            LOG.info("Attachment %s removed", device)
            details = None
            try:
                details = self.plugin_rpc.update_device_down(self.context,
                                                             device,
                                                             self.agent_id,
                                                             cfg.CONF.host)
            except Exception:
                LOG.exception("Error occurred while removing port %s",
                              device)
                resync = True
            if details and details['exists']:
                LOG.info("Port %s updated.", device)
            else:
                LOG.debug("Device %s not defined on plugin", device)
            port_id = self._clean_network_ports(device)
            self.ext_manager.delete_port(self.context,
                                         {'device': device,
                                          'port_id': port_id})
            self.mgr.delete_port(device)

        self.mgr.delete_arp_spoofing_protection(devices)
        return resync
