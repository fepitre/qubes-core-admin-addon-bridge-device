PYTHON ?= python3

ADMIN_API_METHODS_SIMPLE = \
	admin.vm.device.bridge.Assign \
	admin.vm.device.bridge.Assigned \
	admin.vm.device.bridge.Attach \
	admin.vm.device.bridge.Attached \
	admin.vm.device.bridge.Available \
	admin.vm.device.bridge.Detach \
	admin.vm.device.bridge.Set.assignment \
	admin.vm.device.bridge.Unassign

all:
	$(PYTHON) setup.py build

install:
	$(PYTHON) setup.py install -O1 --skip-build --root $(DESTDIR)

	mkdir -p $(DESTDIR)/etc/qubes-rpc
	mkdir -p $(DESTDIR)/etc/qubes/policy.d
	install -m 0644 qubes-rpc-policy/90-admin-bridge-device.policy \
		$(DESTDIR)/etc/qubes/policy.d/90-admin-bridge-device.policy
	for method in $(ADMIN_API_METHODS_SIMPLE); do \
		ln -sf ../../var/run/qubesd.sock \
			$(DESTDIR)/etc/qubes-rpc/$$method || exit 1; \
	done
