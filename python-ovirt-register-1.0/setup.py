from distutils.core import setup

setup(name='ovirt-register',
      version='1.0',
      description='A python module for registering nodes to oVirt Engine',
      author='Douglas Schilling Landgraf',
      author_email='dougsland@redhat.com',
      url='https://github.com/dougsland/ovirt-register/wiki',
      classifiers=[
          'Environment :: Console',
          'Intended Audience :: Developers',
          'License :: GPLv2+',
          'Programming Language :: Python',
          ],
      license= 'GPLv2+',
      packages=['ovirtregister'],
      scripts = ['scripts/ovirt-register'])
