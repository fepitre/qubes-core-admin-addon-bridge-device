# vim: fileencoding=utf-8

import setuptools

if __name__ == '__main__':
    setuptools.setup(
        name='qubesbridgedevice',
        version=open('version').read().strip(),
        author='QubesOS',
        author_email='frederic.pierret@qubes-os.org',
        description='Qubes Bridge Device core-admin extension',
        license='GPL2+',
        url='https://www.qubes-os.org/',
        packages=('qubesbridgedevice',),
        entry_points={
            'qubes.ext': [
                'qubesbridgedevice = qubesbridgedevice:BridgeDeviceExtension',
            ],
            'qubes.devices': [
                'bridge = qubesbridgedevice:BridgeDevice',
            ],
        }
    )
