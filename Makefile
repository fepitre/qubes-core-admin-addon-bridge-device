ADMIN_API_METHODS_SIMPLE = \
	admin.vm.device.bridge.Attach \
	admin.vm.device.bridge.Available \
	admin.vm.device.bridge.Detach \
	admin.vm.device.bridge.List \
	admin.vm.device.bridge.Set.persistent

all:
	python3 setup.py build

install:
	# force /usr/bin before /bin to have /usr/bin/python instead of /bin/python
	PATH="/usr/bin:$$PATH" python3 setup.py install $(PYTHON_PREFIX_ARG) -O1 --skip-build --root $(DESTDIR)

	mkdir -p $(DESTDIR)/etc/qubes-rpc/policy
	for method in $(ADMIN_API_METHODS_SIMPLE); do \
		cp qubes-rpc-policy/$$method.policy $(DESTDIR)/etc/qubes-rpc/policy/$$method; \
		ln -s ../../usr/libexec/qubes/qubesd-query-fast $(DESTDIR)/etc/qubes-rpc/$$method || exit 1; \
	done
