# qubes-core-admin-addon-bridge-device

## Overview

The bridge device allows for the establishment of local networks between various Qubes VMs, enabling seamless communication and connectivity.

This repository contains **dom0 component** for creating a bridge device in Qubes OS.
For **VM Component:**, see [qubes-core-agent-linux-addon-bridge-device](https://github.com/QubesOS-contrib/qubes-core-agent-linux-addon-bridge-device)

## Installation

Install this addon in *dom0* located in the `contrib` repository (see [QubesOS-contrib](https://www.qubes-os.org/doc/installing-contributed-packages/):
```bash
dnf install qubes-core-admin-bridge-device
```

Do the same inside your TemplateVM that will be used for creating the bridge. For example, in Fedora 39:
```bash
dnf install qubes-core-agent-bridge-device-network-manager
```

## Usage

Once installed, you can create a bridge interface in a given AppVM (e.g., "lan-net") using NetworkManager.
This bridge interface, named `br0` in this example, becomes available as a bridge device to be attached.

### Creating a Bridge Interface

```bash
# In the AppVM named "lan-net"
nmcli connection add type bridge ifname br0 con-name br0
```

### Viewing Available Bridges in dom0

```bash
# In dom0
qvm-device bridge
```

### Attaching VMs to the Bridge

You can attach other AppVMs (e.g., "personal") to the created bridge, establishing a local network.

```bash
# In dom0
qvm-device bridge attach personal lan-net:br0
```

You can repeat this process for multiple VMs, creating a classical network between them.
Additionally, physical interfaces can be attached to `br0` linking the Qubes network with external machines.

### Options

Options such as IP address, netmask, and gateway can be specified during attachment:

```bash
# In dom0
qvm-device bridge attach personal lan-net:br0 --option=ip=192.168.0.1 --option=netmask=255.255.255.0 --option=gateway=192.168.0.254
```

### Important Considerations

- **Bridge vs. Qubes Model:**
  Be cautious that using the standard bridge network model differs from the Qubes model based on NAT and component isolation.

- **NetVM and iptables:**
  If your "lan-net" has a NetVM, adjustments to iptables may be necessary.
