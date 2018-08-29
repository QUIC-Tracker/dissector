from setuptools import setup, find_packages

retval = setup(
    name='quic-tracker-dissector',
    version='0.1',
    packages=['quic_tracker.dissector'],
    package_dir={'quic_tracker': 'quic_tracker'},
    url='https://github.com/QUIC-Tracker/dissector',
    license='GNU AGPL v3',
    author='Maxime Piraux',
    author_email='',
    description='A protocol-agnostic dissector',
    install_requires=[],
    include_package_data=True,
)
