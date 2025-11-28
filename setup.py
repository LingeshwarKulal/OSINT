#!/usr/bin/env python3
"""
Setup script for Penetration Testing Toolkit
"""

from setuptools import setup, find_packages
import os

# Read requirements
with open('requirements.txt') as f:
    requirements = f.read().splitlines()

# Read README
with open('README.md', encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='pentest-toolkit',
    version='1.0.0',
    author='Security Team',
    author_email='security@example.com',
    description='A comprehensive penetration testing toolkit',
    long_description=long_description,
    long_description_content_type='text/markdown',
    url='https://github.com/yourusername/pentest-toolkit',
    packages=find_packages(),
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Information Technology',
        'Topic :: Security',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
    ],
    python_requires='>=3.10',
    install_requires=requirements,
    entry_points={
        'console_scripts': [
            'pentest=main:cli',
        ],
    },
    include_package_data=True,
    package_data={
        '': ['*.yaml', '*.txt', '*.md'],
    },
)

# Create necessary directories
directories = [
    'data/wordlists',
    'logs',
    'output',
    'data/exploits',
    'data/payloads'
]

for directory in directories:
    os.makedirs(directory, exist_ok=True)
    print(f'Created directory: {directory}')

print('\n✓ Setup complete!')
print('\nQuick Start:')
print('  python main.py --help')
print('  python main.py subdomain --target example.com')
print('  python main.py portscan --target example.com')
