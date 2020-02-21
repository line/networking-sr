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

import os
import socket
import struct

from oslo_config import cfg
from oslo_log import log as logging

from neutron.agent.linux import external_process
from neutron.conf.agent import dhcp as dhcp_config

LOG = logging.getLogger(__name__)

DNSMASQ_PROCESS_UUID = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
DNSMASQ_HOST_DIR = "dhcp-hosts.d"
DNSMASQ_OPTS_DIR = "dhcp-opts.d"
DNSMASQ_LEASE_DIR = "dhcp-lease"
DNSMASQ_PID_DIR = "dnsmasq-pids"
DNSMASQ_TAG_LEN = 8
DHCP_DEFAULT_ROOT = "0.0.0.0/0,%(gateway_ip)s"

SUBNET_DEDICATED_DHCP = 'subnet-dedicated-dhcp'

# NOTE: Use same configuration as neutron-dhcp-agent
# But in this agent, we only use dnsmasq_dns_servers
# which will be used as a default upstream dns server
# If we specify dns_servers in subnet, these dns servers
# will be used intead of cfg.CONF.dnsmasq_dns_servers
cfg.CONF.register_opts(dhcp_config.DNSMASQ_OPTS)


class DnsmasqManager(object):

    @classmethod
    def _get_config_dir(cls, directory_name):
        """Get a path of dnsmasq config directory

        Args:
            directory_name(String): directory name
        Return:
            path(String): absolute path to directory_name
        """
        return os.path.join(cfg.CONF.state_path, directory_name)

    @classmethod
    def get_host_entries(cls, re_raise=True):
        """Get all dhcp host entry names(device name)

        Args:
            re_raise(Bool): whether if Exception should be propagated or not
        Return:
            host_entries(list<String>): existing host entry names(device name)
        """
        host_entries = []
        try:
            host_entries = os.listdir(cls._get_config_dir(DNSMASQ_HOST_DIR))
        except Exception as e:
            LOG.warning("Failed to listdir %s: %s",
                        cls._get_config_dir(DNSMASQ_HOST_DIR), e)
            if re_raise:
                raise
        return host_entries

    @classmethod
    def sync_host_entries(cls, get_interface_func, add_missing_entry_func):
        """This method try to ensure following about dhcp host entry

           * We have all dhcp host entry for existing tap device
              -> Add tap device into list that contains device being
                 re-configured in next iteration
           * We don't have orphan dhcp host entry which is no longer used

            Args:
                get_interface_func(function): function to get existing device
                add_missing_entry_func(function): function to add device into
                                                 missing_entry list
            Return:
                None
            Raise:
                OSError: if we failed to load existing host entries to prevent
                         mis-behaviour (could be possible to recognise all
                         host entries as missing)
        """
        LOG.debug("Start sync_host_entries")
        host_entries = cls.get_host_entries()
        host_entries = set(host_entries)
        devices = get_interface_func()
        devices = set(devices)

        orphan_entries = host_entries - devices
        missing_entries = devices - host_entries

        for oe in orphan_entries:
            LOG.info("Found orhpan entry and Delete %s", oe)
            cls.delete_fixedip_entry(oe)

        for me in missing_entries:
            LOG.warning("Found missing dhcp host entry for %s", me)
            add_missing_entry_func(me)
        LOG.debug("Finish sync_host_entries")

    @classmethod
    def initialize(cls, monitor):
        """This method should be called before any other method being called.

        Ensure to have required directory and spawn dnsmasq for all subnets
        Args:
            None
        Return:
            None
        """
        for config_dir_name in (DNSMASQ_OPTS_DIR,
                                DNSMASQ_HOST_DIR,
                                DNSMASQ_LEASE_DIR):
            config_dir = cls._get_config_dir(config_dir_name)
            if not os.path.exists(config_dir):
                LOG.info("Create %s directory" % config_dir)
                os.makedirs(config_dir)

        # FIXME(Yuki Nishiwaki)
        # This is the temporally workaround for older dnsmasq than 2.7.9
        # See more detail in def get_dnsmasq_cmd methods
        for dummy_file in ("dummy_hosts", "dummy_opts"):
            dummy_file_path = os.path.join(cfg.CONF.state_path, dummy_file)
            if not os.path.exists(dummy_file_path):
                f = open(dummy_file_path, 'w')
                f.close()

        callback = cls.get_dnsmasq_cmd(DNSMASQ_PROCESS_UUID)
        pm = cls.get_process_manager(DNSMASQ_PROCESS_UUID, cfg.CONF, callback)
        pm.enable()
        monitor.register(DNSMASQ_PROCESS_UUID, SUBNET_DEDICATED_DHCP, pm)

    @classmethod
    def get_tag_name(cls, subnet_id):
        """Return tag name

        Args:
            subnet_id(String): subnet uuid
        Return:
            subnet_tag(String): first DNSMASQ_TAG_LEN character of subnet_id
        """
        return subnet_id[:DNSMASQ_TAG_LEN]

    @classmethod
    def _transform_cidr_notation_to_netmask(cls, cidr_notation):
        """Return netmask transformed by cidr_notation

        Args:
            cidr_notation(String): network cidr notation
        Return:
            netmask(String): netmask
        """
        host_bits = 32 - int(cidr_notation)
        netmask = socket.inet_ntoa(
            struct.pack('!I', (1 << 32) - (1 << host_bits)))
        return netmask

    @classmethod
    def ensure_dhcp_opts(cls, subnet_id, defaultgw, static_routes,
                         cidr_notation, nameservers):
        """Ensure we have dhcp_opts file with passed configuration

        Args:
            subnet_id(String): subnet uuid
            defaultgw(String): ip address without cider notation
                              like 192.168.0.1
            static_routes(list<String>): ["<cidr>,<gateway_ip>",]
            cidr_notation(String): network cidr notation i.e. 24 or 16...
            nameservers(list<String>): ["<nameserver>", ]
        Return:
            succeed_flg(Bool): True if succeed in ensuring dhcp option for
                               subnet
        """
        # NOTE: If subnet doesn't specify nameservers,
        # we use dnsmasq_dns_servers instead
        if len(nameservers) == 0:
            nameservers = cfg.CONF.dnsmasq_dns_servers
        target_opts_path = os.path.join(
            cls._get_config_dir(DNSMASQ_OPTS_DIR), subnet_id)

        netmask = cls._transform_cidr_notation_to_netmask(cidr_notation)
        routes = [DHCP_DEFAULT_ROOT % {"gateway_ip": defaultgw}, ]
        routes += static_routes
        opt_pre = "tag:%s," % cls.get_tag_name(subnet_id)
        try:
            LOG.info("Try to create %s", target_opts_path)
            with open(target_opts_path, 'w') as f:
                f.write(opt_pre +
                        "option:router," + defaultgw + "\n")
                f.write(opt_pre +
                        "249," + ",".join(routes) + "\n")
                f.write(
                    opt_pre +
                    "option:classless-static-route," + ",".join(routes) + "\n")
                f.write(opt_pre +
                        "option:netmask," + netmask + "\n")
                if nameservers:
                    f.write(opt_pre +
                            "option:dns-server," +
                            ",".join(nameservers) + "\n")
        except Exception as e:
            LOG.error("Can not create dhcp opts %s: %s",
                      target_opts_path, e)
            return False
        return True

    @classmethod
    def delete_fixedip_entry(cls, device_name):
        """Delete host entry named as device_name

        And also this sends SIGHUP to dnsmasq to reload config

        Args:
            device_name(String): dhcp host entry name
        Return:
            None
        """
        try:
            entry = os.path.join(cls._get_config_dir(DNSMASQ_HOST_DIR),
                                 device_name)
            os.remove(entry)
            pm = cls.get_process_manager(DNSMASQ_PROCESS_UUID, cfg.CONF)
            pm.reload_cfg()
        except Exception as e:
            # Even If we failed to delete dhcp entry,
            # that old dhcp entry are not harmful immediately
            # So we ignore that after let operator know
            LOG.warning("Can not delete %s: %s", entry, e)

    @classmethod
    def add_fixedip_entry(cls, subnet_id, device_name, macaddr, ipaddr):
        """Added host entry with passed configuration

        Args:
            subnet_id(String): subnet uuid
            device_name(String): device name being used for dhcp host entry
                                 name
            macaddr(String): target mac address
            ipaddr(String): the ip address being issued against macaddr
        Return:
            succeed_flg(Bool): True if it succeed in creating host entry
        """
        target_host_path = os.path.join(
            cls._get_config_dir(DNSMASQ_HOST_DIR), device_name)
        try:
            LOG.info("Try to create %s", target_host_path)
            with open(target_host_path, 'w') as f:
                f.write("%s,%s,set:%s\n" %
                        (macaddr, ipaddr,
                         subnet_id[:DNSMASQ_TAG_LEN]))
        except Exception as e:
            LOG.error("Can not create host entry %s: %s",
                      target_host_path, e)
            return False
        return True

    @classmethod
    def get_dnsmasq_cmd(cls, uuid):
        """Get dnsmasq command being executed

        Args:
            uuid(String): uuid to identify dnsmasq process
        Return:
            callback(function): function to return dnsmasq command with
                                passed argument
        """
        def callback(pid_file):
            # TODO(Yuki Nishiwaki) Add --except-interface physical interface
            lease_file = os.path.join(
                cls._get_config_dir(DNSMASQ_LEASE_DIR), uuid)

            if cfg.CONF.dhcp_lease_duration == -1:
                lease = 'infinite'
            else:
                lease = '%ss' % cfg.CONF.dhcp_lease_duration

            dnsmasq_cmd = [
                'dnsmasq', '--pid-file=%s' % pid_file,
                '--dhcp-optsdir=%s' % cls._get_config_dir(
                    DNSMASQ_OPTS_DIR),
                '--dhcp-hostsdir=%s' % cls._get_config_dir(
                    DNSMASQ_HOST_DIR),
                '--dhcp-leasefile=%s' % lease_file,
                '--bind-dynamic', '--port=0',
                '--domain=%s' % cfg.CONF.dns_domain,
                '--dhcp-range=0.0.0.0,static,128.0.0.0,%s' % lease,
                '--dhcp-range=128.0.0.0,static,128.0.0.0,%s' % lease]
            # FIXME(Yuki Nishiwaki)
            # The older dnsmasq than 2.7.9 have the bug not clearing existing
            # dhcp-hosts, dhcp-opts config and just re-load config when
            # it got SIGHUP, but if we passed --dhcp-hostsfile, --dhcp-optsfile
            # option, dnmsasq correclty clear exisiting config and re-load.
            dnsmasq_cmd += [
                '--dhcp-hostsfile=%s' % os.path.join(
                    cfg.CONF.state_path, 'dummy_hosts'),
                '--dhcp-optsfile=%s' % os.path.join(
                    cfg.CONF.state_path, 'dummy_opts')]
            return dnsmasq_cmd
        return callback

    @classmethod
    def get_process_manager(cls, uuid, conf, callback=None):
        """Get process manager for specific command

        Args:
            uuid(String): subnet uuid
            conf: cfg.CONF
            callback: function to return command list
        Return:
            pm(neutron.agent.linux.external_process.ProcessManager):
        """
        return external_process.ProcessManager(
            conf=conf, uuid=uuid,
            pid_file=cls._get_config_dir(DNSMASQ_PID_DIR) + "/" + uuid,
            default_cmd_callback=callback,
            run_as_root=True)
