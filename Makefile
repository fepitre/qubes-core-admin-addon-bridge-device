all:
	python3 setup.py build

install:
	# force /usr/bin before /bin to have /usr/bin/python instead of /bin/python
	PATH="/usr/bin:$$PATH" python3 setup.py install $(PYTHON_PREFIX_ARG) -O1 --skip-build --root $(DESTDIR)

	# default RPC policy
	install -D -m 0664 -- qubes-rpc-policy/80-admin-default-bridge.policy $(DESTDIR)/etc/qubes/policy.d/80-admin-default-bridge.policy
