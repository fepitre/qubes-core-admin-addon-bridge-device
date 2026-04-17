# -*- encoding: utf-8 -*-
#
# The Qubes OS Project, http://www.qubes-os.org
#
# Copyright (C) 2019 Frédéric Pierret <frederic.pierret@qubes-os.org>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, see <http://www.gnu.org/licenses/>.

"""
qubes-core-admin extension for handling Bridge Device
"""

import asyncio
import ipaddress
import random
import re
import string
from typing import List, Optional, cast

import lxml.etree

import qubes.device_protocol
import qubes.devices
import qubes.exc
import qubes.ext
from qubes.devices import Port

# bridge name: lowercase alnum + hyphen, max 12 chars
name_re = re.compile(r"\A[a-z0-9-]{1,12}\Z")


def rand_mac():
    # Xen OUI (00:16:3e), last 3 octets random
    return (
        f"00:16:3e:{random.randint(0, 255):02x}"
        f":{random.randint(0, 255):02x}"
        f":{random.randint(0, 255):02x}"
    )


def check_mac(mac):
    """
    Check MAC format.
    """
    mac_regex = re.compile(r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$")
    return bool(re.match(mac_regex, mac))


def check_ip(ip):
    """
    Check IP address format.
    """
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def get_netmask_from_prefix(prefix):
    try:
        network_conf = ipaddress.IPv4Interface(f"0.0.0.0/{prefix}")
    except ipaddress.NetmaskValueError as exc:
        raise qubes.exc.QubesValueError(f"Invalid prefix: {prefix}") from exc
    return str(network_conf.network.netmask)


def get_prefix_from_netmask(netmask):
    try:
        network_conf = ipaddress.IPv4Interface(f"0.0.0.0/{netmask}")
    except ipaddress.NetmaskValueError as exc:
        raise qubes.exc.QubesValueError(f"Invalid netmask: {netmask}") from exc
    return str(network_conf.network.prefixlen)


def get_subnet(ip, netmask):
    try:
        network_conf = ipaddress.IPv4Interface(f"{ip}/{netmask}")
    except (ipaddress.AddressValueError, ipaddress.NetmaskValueError) as exc:
        raise qubes.exc.QubesValueError(
            f"Invalid ip/netmask: {ip}/{netmask}"
        ) from exc
    return str(network_conf.network.network_address)


class BridgeDevice(qubes.device_protocol.DeviceInfo):
    # pylint: disable=too-few-public-methods

    def __init__(self, port: Port):
        if port.devclass != "bridge":
            raise qubes.exc.QubesValueError(
                f"Incompatible device class for input port: {port.devclass}"
            )
        super().__init__(port)
        self._description: Optional[str] = None

    @property
    def description(self) -> str:
        """
        Human readable device description.
        """
        if self._description is None:
            if not self.backend_domain.is_running():
                return self.port_id
            # sanitize untrusted QubesDB string to safe printable ASCII
            safe_set = {
                ord(c)
                for c in string.ascii_letters + string.digits + "()+,-.:=_/ "
            }
            untrusted_desc = self.backend_domain.untrusted_qdb.read(
                f"/qubes-bridge-devices/{self.port_id}/desc"
            )
            if not untrusted_desc:
                return ""
            desc = "".join(
                (chr(c) if c in safe_set else "_") for c in untrusted_desc
            )
            self._description = desc
        return self._description

    @property
    def interfaces(self) -> List[qubes.device_protocol.DeviceInterface]:
        return [qubes.device_protocol.DeviceInterface("******", "bridge")]

    @property
    def device_id(self) -> str:
        """
        Unique identifier for this bridge device (port-based).
        """
        return self.port_id

    @property
    def manufacturer(self) -> str:
        return f"hosted by {self.backend_domain!s}"


class BridgeDeviceExtension(qubes.ext.Extension):
    # pylint: disable=unused-argument,no-self-use

    @qubes.ext.handler("domain-init", "domain-load")
    def on_domain_init_load(self, vm, event):
        vm.watch_qdb_path("/qubes-bridge-devices")

    @qubes.ext.handler("domain-qdb-change:/qubes-bridge-devices")
    def on_qdb_change(self, vm, event, path):
        vm.fire_event("device-list-change:bridge")

    @qubes.ext.handler("device-list:bridge")
    def on_device_list_bridge(self, vm, event):
        if not vm.is_running():
            return

        untrusted_qubes_devices = vm.untrusted_qdb.list(
            "/qubes-bridge-devices/"
        )
        # path is /qubes-bridge-devices/<name>/attr; index 2 is the bridge name
        untrusted_idents = set(
            untrusted_path.split("/", 3)[2]
            for untrusted_path in untrusted_qubes_devices
        )

        for untrusted_ident in untrusted_idents:
            if not name_re.match(untrusted_ident):
                vm.log.warning(
                    f"{vm.name} vm's device path name contains"
                    " unsafe characters. Skipping it."
                )
                continue

            ident = untrusted_ident
            device_info = self.device_get(vm, ident)
            if device_info:
                yield device_info

    @qubes.ext.handler("device-get:bridge")
    def on_device_get_bridge(self, vm, event, port_id):
        if not vm.is_running():
            return
        if not vm.app.vmm.offline_mode:
            device_info = self.device_get(vm, port_id)
            if device_info:
                yield device_info

    @qubes.ext.handler("device-list-attached:bridge")
    def on_device_list_attached(self, vm, event, **kwargs):
        if not vm.is_running():
            return

        xml_desc = lxml.etree.fromstring(vm.libvirt_domain.XMLDesc())

        for iface in xml_desc.findall("devices/interface"):
            if iface.get("type") != "bridge":
                continue

            backend_domain_node = iface.find("backenddomain")
            if backend_domain_node is None:
                continue

            dom_name = backend_domain_node.get("name")
            if dom_name == "Domain-0":
                dom_name = "dom0"  # libvirt calls it Domain-0, qubes uses dom0
            backend_domain = vm.app.domains[dom_name]

            bridge_name_node = iface.find("source")
            if bridge_name_node is None:
                continue
            ident = bridge_name_node.get("bridge")

            options = {}

            mac_node = iface.find("mac")
            if mac_node is None:
                continue
            mac = mac_node.get("address")
            if not mac:
                continue
            options["mac"] = mac

            ip_node = iface.find("ip")
            if ip_node is not None:
                ip = ip_node.get("address")
                prefix = ip_node.get("prefix")
                if ip and prefix:
                    options["ip"] = ip
                    options["netmask"] = get_netmask_from_prefix(prefix)

            route_node = iface.find("route")
            if route_node is not None:
                gateway = route_node.get("gateway")
                if gateway:
                    options["gateway"] = gateway

            yield (BridgeDevice(Port(backend_domain, ident, "bridge")), options)

    @qubes.ext.handler("device-pre-attach:bridge")
    def on_device_pre_attach_bridge(self, vm, event, device, options):
        for option, value in options.items():
            if option == "mac":
                if not check_mac(value):
                    raise qubes.exc.QubesValueError(
                        f"Invalid MAC address: {value}"
                    )
            elif option in ("ip", "netmask", "gateway"):
                if not check_ip(value):
                    raise qubes.exc.QubesValueError(
                        f"Invalid {option} address: {value}"
                    )
            else:
                raise qubes.exc.QubesValueError(f"Unsupported option {option}")

        if not device.backend_domain.is_running():
            raise qubes.exc.QubesVMNotRunningError(
                device.backend_domain,
                f"Domain {device.backend_domain.name} needs to be"
                " running to attach device from it",
            )

        if "mac" not in options:
            mac = self.generate_unused_mac(vm)
            if mac is None:
                raise qubes.exc.QubesValueError(
                    f"Could not generate an unused MAC address for {vm.name}"
                )
            options["mac"] = mac

        # When called at spawn time and not while qube is running,
        # qubesdb is not initialised yet
        if event != "domain-spawn" and vm.is_running():
            self.create_qdb_entries(vm, options)

    @qubes.ext.handler("device-attach:bridge")
    def on_device_attach_bridge(self, vm, event, device, options):
        if not vm.is_running():
            return

        vm.libvirt_domain.attachDevice(
            self.generate_bridge_xml(vm, device, options)
        )

    @qubes.ext.handler("device-pre-detach:bridge")
    def on_device_pre_detach_bridge(self, vm, event, port):
        if not vm.is_running():
            return

        for attached_device, options in self.on_device_list_attached(vm, event):
            if attached_device.port == port:
                self.remove_qdb_entries(vm, options)
                break

    @qubes.ext.handler("device-detach:bridge")
    def on_device_detach_bridge(self, vm, event, port):
        if not vm.is_running():
            return

        for attached_device, options in self.on_device_list_attached(vm, event):
            if attached_device.port == port:
                vm.libvirt_domain.detachDevice(
                    self.generate_bridge_xml(vm, attached_device, options)
                )
                break

    @qubes.ext.handler("domain-pre-start")
    async def on_domain_pre_start(self, vm, event, start_guid, **kwargs):
        for bridge in vm.devices["bridge"].get_assigned_devices():
            try:
                backenddomain = vm.app.domains[bridge.backend_domain.name]
            except KeyError:
                vm.log.error(
                    f"Cannot find backend domain '{bridge.backend_domain.name}'"
                )
                continue

            if backenddomain.qid != 0:
                if not backenddomain.is_running():
                    await backenddomain.start(
                        start_guid=start_guid, notify_function=None
                    )

                wait_count = 0
                vm.log.info(
                    f"Waiting for {bridge.backend_domain.name}"
                    f":{bridge.port_id} being available"
                )
                # poll at 1s intervals; >120 iterations = ~120s timeout
                while not self.device_get(backenddomain, bridge.port_id):
                    wait_count += 1
                    if wait_count > 120:
                        vm.log.error(
                            f"Timeout while waiting for"
                            f" {bridge.port_id} to be available"
                        )
                        break
                    await asyncio.sleep(1.0)

    @qubes.ext.handler("domain-spawn")
    def on_domain_spawn(self, vm, event, start_guid, **kwargs):
        for bridge in vm.devices["bridge"].get_assigned_devices():
            # Take a single mutable copy so that mac generated in
            # on_device_pre_attach_bridge is visible to on_device_attach_bridge.
            # bridge.options returns a fresh copy on each access.
            options = dict(bridge.options)
            self.on_device_pre_attach_bridge(vm, event, bridge.device, options)
            self.on_device_attach_bridge(vm, event, bridge.device, options)

    @qubes.ext.handler("domain-qdb-create")
    def on_qdb_create(self, vm, event, **kwargs):
        # bridge.options never contains the generated mac (not persisted from
        # spawn). Read mac back from libvirt XML via on_device_list_attached
        # and merge with the stored options (ip/netmask/gateway).
        assigned = {
            b.port_id: b.options
            for b in vm.devices["bridge"].get_assigned_devices()
        }
        for dev, attached_opts in self.on_device_list_attached(vm, event):
            if dev.port_id in assigned:
                merged = {**assigned[dev.port_id], **attached_opts}
                self.create_qdb_entries(vm, merged)

    @qubes.ext.handler("domain-pre-shutdown")
    def on_domain_pre_shutdown(self, vm, event, **kwargs):
        attached_vms = [
            domain for domain in self.attached_vms(vm) if domain.is_running()
        ]
        if attached_vms and not kwargs.get("force", False):
            names = ", ".join(domain.name for domain in attached_vms)
            raise qubes.exc.QubesVMError(
                vm,
                f"There are bridges attached to this VM: {names}",
            )

    @staticmethod
    def device_get(vm, port_id):
        """
        Read device info from QubesDB; returns None if not present.
        """
        untrusted_qubes_device_attrs = vm.untrusted_qdb.list(
            f"/qubes-bridge-devices/{port_id}/"
        )
        if not untrusted_qubes_device_attrs:
            return None
        return BridgeDevice(
            Port(backend_domain=vm, port_id=port_id, devclass="bridge")
        )

    @staticmethod
    def generate_unused_mac(vm) -> Optional[str]:
        """
        Return a MAC not already used by any interface in the domain XML.
        """
        xml = vm.libvirt_domain.XMLDesc()
        parsed_xml = lxml.etree.fromstring(xml)
        mac_nodes = cast(
            List[lxml.etree._Element],
            parsed_xml.xpath("//domain/devices/interface/mac"),
        )
        used = [node.get("address") for node in mac_nodes]

        available_macs = (rand_mac() for _ in range(32))  # 32 attempts max

        for mac in available_macs:
            if mac not in used:
                return mac
        return None

    @staticmethod
    def generate_bridge_xml(vm, device, options):
        options_ext = dict(options)
        if options.get("netmask", False):
            options_ext["prefix"] = get_prefix_from_netmask(options["netmask"])
            options_ext["subnet"] = get_subnet(
                options["ip"], options["netmask"]
            )

        bridge_xml = """
            <interface type="bridge">
                <source bridge="{{device.port_id}}" />
                <mac address="{{options.get('mac')}}" />
                {%- if device.backend_domain.name != 'dom0' %}
                <backenddomain name="{{device.backend_domain.name}}" />
                {%- endif %}
                <script path="vif-bridge" />
                {%- if options.get('ip') and options.get('prefix') %}
                <ip address="{{options.get('ip')}}" prefix="{{options.get('prefix')}}" />
                {%- if options.get('gateway') %}
                <route family="ipv4" address="{{options.get('subnet')}}" prefix="{{options.get('prefix')}}" gateway="{{options.get('gateway')}}" />
                {%- endif %}
                {%- endif %}
            </interface>
        """

        return vm.app.env.from_string(bridge_xml).render(
            device=device, options=options_ext
        )

    def attached_vms(self, vm):
        for domain in vm.app.domains:
            for attached_device, _ in self.on_device_list_attached(
                domain, event=None
            ):
                if attached_device.backend_domain is vm:
                    yield domain

    @staticmethod
    def create_qdb_entries(vm, options):
        if "ip" in options and "netmask" in options:
            mac = options["mac"]
            vm.untrusted_qdb.write(f"/net-config/{mac}/ip", options["ip"])
            vm.untrusted_qdb.write(
                f"/net-config/{mac}/netmask", options["netmask"]
            )

            if "gateway" in options:
                vm.untrusted_qdb.write(
                    f"/net-config/{mac}/gateway", options["gateway"]
                )

    @staticmethod
    def remove_qdb_entries(vm, options):
        mac = options["mac"]
        vm.untrusted_qdb.rm(f"/net-config/{mac}/ip")
        vm.untrusted_qdb.rm(f"/net-config/{mac}/netmask")
        vm.untrusted_qdb.rm(f"/net-config/{mac}/gateway")
