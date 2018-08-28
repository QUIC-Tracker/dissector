from setuptools import setup, find_packages

retval = setup(
    name='quic-tracker-dissector',
    version='0.1',
    packages=find_packages(),
    url='https://github.com/QUIC-Tracker/dissector',
    license='GNU AGPL v3',
    author='Maxime Piraux',
    author_email='',
    description='A protocol-agnostic dissector',
    install_requires=[],
    include_package_data=True,
)
