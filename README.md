# NAPALM driver for fortios

Modified to add get_config and get_environment for use with netbox.

This is a [NAPALM](https://napalm.readthedocs.io/en/latest/) driver for fortios (fortigate) using rest API to be able, for now, retrieving some information like:

- interfaces
- interface ip
- firewall policies

## Install

There is no PyPi repo and original author went stale, to install use command line:

```shell
pip install git+https://github.com/ekrichbaum/napalm-fortios.git@<release version>
```

## Usage

you can use this new driver, example with napalm command line:

```
napalm --user myuser --vendor fortios my-forti.fortigate.company.com --optional_args "vdom=root" call get_firewall_policies
```

