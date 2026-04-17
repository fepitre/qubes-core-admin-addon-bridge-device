# vim: fileencoding=utf-8

import setuptools

if __name__ == '__main__':
    setuptools.setup(
        name='qubesbridgedevice',
        version=open('version').read().strip(),
        author='Qubes OS Project',
        author_email='frederic.pierret@qubes-os.org',
        description='Qubes Admin API extension for bridge network devices',
        license='GPL2+',
        url='https://www.qubes-os.org/',
        packages=('qubesbridgedevice',),
        install_requires=[
            'lxml',
            'jinja2',
        ],
        entry_points={
            'qubes.ext': [
                'qubesbridgedevice = qubesbridgedevice:BridgeDeviceExtension',
            ],
            'qubes.devices': [
                'bridge = qubesbridgedevice:BridgeDevice',
            ],
        }
    )
