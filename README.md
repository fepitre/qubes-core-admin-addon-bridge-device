# qubes-core-admin-addon-bridge-device

A [qubes-core-admin](https://github.com/QubesOS/qubes-core-admin) extension
that exposes bridge network interfaces as first-class Qubes OS devices under
the `bridge` device class.

## Overview

This addon registers a new device class (`bridge`) with the Qubes Admin API.
Bridge interfaces advertised by a backend domain via QubesDB are discoverable,
attachable, and persistently assignable to frontend qubes, just like block or
PCI devices, using the standard `admin.vm.device.bridge.*` API methods.

## Requirements

- `qubes-core-dom0` (Qubes OS 4.2+)
- `python3-lxml`
- `python3-jinja2`
- `python3-qubesdb`

## How it works

### Device discovery

A backend domain (including `dom0`) writes bridge metadata to QubesDB:

```
/qubes-bridge-devices/<bridge-name>/desc   Human-readable description
```

The addon watches this path and fires `device-list-change:bridge` whenever
it changes, so the Admin API device list stays live.

### Attachment options

When attaching or assigning a bridge device the following options are accepted:

| Option    | Required | Description                              |
|-----------|----------|------------------------------------------|
| `mac`     | no       | MAC address for the guest vif (generated randomly if absent) |
| `ip`      | no       | IPv4 address to assign inside the guest  |
| `netmask` | no       | Subnet mask (required if `ip` is set)    |
| `gateway` | no       | Default gateway (optional)               |

Network configuration is written to `/net-config/<mac>/{ip,netmask,gateway}`
in the frontend domain's QubesDB, where guest networking scripts can read it.

### Persistent assignment

Bridges can be assigned to a qube so they are attached automatically at
startup:

```
qvm-device bridge assign --ro <frontend-vm> <backend-vm>:<bridge-name>
```

Assignment modes (`auto-attach`, `ask-to-attach`, `required`) are supported
via `admin.vm.device.bridge.Set.assignment`.

When a bridge is assigned as `required` (or any non-manual mode), the addon
ensures the backend domain is running and the bridge is present in QubesDB
before the frontend domain is allowed to start.

## Admin API methods

All methods follow the standard Qubes Admin API device convention:

| Method                                    | Description                          |
|-------------------------------------------|--------------------------------------|
| `admin.vm.device.bridge.Available`        | List bridges exposed by a VM         |
| `admin.vm.device.bridge.Assigned`         | List persistently assigned bridges   |
| `admin.vm.device.bridge.Attached`         | List currently attached bridges      |
| `admin.vm.device.bridge.Assign`           | Persistently assign a bridge         |
| `admin.vm.device.bridge.Unassign`         | Remove a persistent assignment       |
| `admin.vm.device.bridge.Attach`           | Attach a bridge to a running VM      |
| `admin.vm.device.bridge.Detach`           | Detach a bridge from a running VM    |
| `admin.vm.device.bridge.Set.assignment`   | Change the assignment mode           |
