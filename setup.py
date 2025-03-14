from setuptools import setup, find_packages
import pathlib

here = pathlib.Path(__file__).parent.resolve()
long_description = (here/'README.md').read_text(encoding='utf-8')

setup(
    name='SNTOTPConverter',
    version='1.0.0',
    description='Script for importing/exporting TOTP 2-factor authentication codes for Standard Notes.',
    long_description=long_description,
    long_description_content_type='text/markdown',
    author='LittleBit',
    author_email='littlebit@littlebitstudios.com',
    license='MIT',
    license_files=['LICENSE'],
    packages=find_packages(),
    entry_points={'console_scripts': ['sntotpconverter=SNTOTPConverter:main']},
    classifiers = [
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent'
    ]
)