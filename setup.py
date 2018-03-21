from distutils.core import setup

setup(
    # Application name:
    name="HoardErebor",

    # Version number (initial):
    version="0.3.0",

    # Application author details:
    author="Dan Lipert",
    author_email="dan@hoardinvest.com",

    # Packages
    packages=["erebor"],

    # Include additional files into the package
    include_package_data=True,

    # Details
    url="http://www.hoardinvest.com",

    #
    # license="LICENSE.txt",
    description="Erebor backend",

    # long_description=open("README.txt").read(),

    # Dependent packages (distributions)
    install_requires=[
        "aiohttp==2.2.5",
        "blinker==1.3",
        "chardet==2.3.0",
        "configobj==5.0.6",
        "flexmock==0.10.2",
        "jsonpatch==1.10",
        "jsonpointer==1.9",
        "MarkupSafe==0.23",
        "oauthlib==1.0.3",
        "prettytable==0.7.2",
        "psycopg2==2.7.3.1",
        "pyasn1==0.1.9",
        "pytest==3.2.1",
        "requests==2.18.4",
        "sanic==0.6.0",
        "Sanic-Cors==0.6.0.2",
        "six==1.10.0",
        "testing.postgresql==1.3.0",
        "twilio==6.6.3",
        "urllib3==1.22",
    ],
)
