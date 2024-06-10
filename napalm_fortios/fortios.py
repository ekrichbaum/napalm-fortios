# Copyright 2015 Spotify AB. All rights reserved.
#
# The contents of this file are licensed under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with the
# License. You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations under
# the License.
import socket,sys,easysnmp,time,re,json,pprint

from fortiosapi import FortiOSAPI
from napalm.base.base import NetworkDriver

def intfix(i):
    return int(i) if i.isdigit() else 0

def meter_fortigate(host,community):
    data = {}
    try:
        snmp = easysnmp.Session(hostname=host,community=community,version=2)

        total_sys_cpu = snmp.get('.1.3.6.1.4.1.12356.101.4.1.3.0').value
        cpu_type_tr = {'.1.3.6.1.4.1.12356.101.4.4.3.2':'cpu','.1.3.6.1.4.1.12356.101.4.4.3.8':'npu',
               'SNMPv2-SMI::enterprises.12356.101.4.4.3.2':'cpu','SNMPv2-SMI::enterprises.12356.101.4.4.3.8':'npu',}

        cpus = {}
        npu_id = 0
        for cpu_obj in snmp.bulkwalk('.1.3.6.1.4.1.12356.101.4.4.2.1.4'):
            idx = int(cpu_obj.oid.split('.')[-1])
            cpu_type = cpu_type_tr.get(cpu_obj.value,'cpu')
            if not idx in cpus:
                cpus[idx] = {}
            if cpu_type == 'cpu':
                cpu_name = f"{cpu_type}{idx}"
            else:
                cpu_name = f"{cpu_type}{npu_id}"
                npu_id +=1
            cpus[idx] = {'name':cpu_name}

        for cpu_usage_obj in snmp.bulkwalk('.1.3.6.1.4.1.12356.101.4.4.2.1.2'):
            idx = int(cpu_usage_obj.oid.split('.')[-1])

            val = int(cpu_usage_obj.value)
            if idx in cpus:
                cpus[idx]['%usage'] = val

        cpus_results = {}
        for c in cpus.values():
            cpus_results[c['name']] = {'%usage':c['%usage']}

        data['cpu'] = cpus_results

        total_used_pr= intfix(snmp.get('.1.3.6.1.4.1.12356.101.4.1.4.0').value)
        mem_total = intfix(snmp.get('.1.3.6.1.4.1.12356.101.4.1.5.0').value)
        mem_used  = int(float(mem_total) * total_used_pr/100.0)

        data['memory'] = {"available_ram":mem_total,"used_ram":mem_used}

        pp = pprint.PrettyPrinter(indent=1)
        with open('/home/netbox/netbox-debug.log','w') as File:
            File.write(pp.pformat(data['memory']))

        environs = {}
        for obj in snmp.bulkwalk('.1.3.6.1.4.1.12356.101.4.3.2.1.2'):
            name = obj.value
            idx = int(obj.oid.split('.')[-1])
            environs[idx] = {"name":name}
        for obj in snmp.bulkwalk('.1.3.6.1.4.1.12356.101.4.3.2.1.3'):
            val = obj.value
            idx = int(obj.oid.split('.')[-1])
            if idx in environs:
                environs[idx]['value'] = val

        temps = {}
        fans = {}
        power = {}
        for i in environs.values():
            name = i['name']
            value = i['value']
            if 'Temp' in name or 'CPU Core' in name:
                temps[name] = {"temperature":value}
            if 'Fan' in name:
                boo = 'False'
                if int(value) > 0:
                    boo = 'True'
                fans[name] = {"status":boo}
            if 'VIN' in name or 'VOUT' in name:
                boo = 'False'
                if float(value) > 0:
                    boo = 'True'
                power[name] = {"status":boo}

        data=json.dumps(
                  {"cpu":cpus_results,
                   "memory":{"available_ram":mem_total,"used_ram":mem_used},
                   "fans":fans,
                   "temperature":temps,
                   "power":power,
                    })

    except Exception as e:
        print(e)
    finally:
        return data


class FortiOSDriver(NetworkDriver):
    def __init__(self, hostname, username, password, timeout=60, optional_args=None):
        self.hostname = hostname
        self.username = username
        self.password = password
        self.timeout = timeout

        self.community = optional_args.get('community', 'public')
        self.port = optional_args.get('port', 22)

        if optional_args is not None:
            self.vdom = optional_args.get('fortios_vdom', None)
        else:
            self.vdom = None
        self.device = FortiOSAPI()

    def open(self):
        self.device.login(self.hostname, self.username, self.password, verify=False, timeout=self.timeout)

    def close(self):
        self.device.logout()

    def is_alive(self):
        """Returns a flag with the state of the SSH connection."""
        alive = True
        try:
            self.device.check_session()
        except Exception:
            alive = False
        return {
            'is_alive': alive,
        }

    def get_interfaces(self):
        interface_statistics = {}
        interfaces = self.device.monitor('system/interface', 'select')['results']
        for name, interface in interfaces.items():
            interface_statistics[name] = {
                'is_up': interface['link'],
                'is_enabled': interface['link'],
                'description': '',
                'mac_address': interface['mac'],
                'last_flapped': -1,
                'speed': interface['speed'],
                'mtu': -1,
            }

        return interface_statistics

    def get_interfaces_ip(self):
        interface_ips = {}
        interfaces = self.device.monitor('system/interface', 'select')['results']
        for name, interface in interfaces.items():
            if self._is_ipv4(interface['ip']):
                interface_ips[name] = {
                    'ipv4': {
                        interface['ip']: {
                            'prefix_length': 32
                        }
                    }
                }
            else:
                interface_ips[name] = {
                    'ipv6': {
                        interface['ip']: {
                            'prefix_length': 127
                        }
                    }
                }
        return interface_ips

    @staticmethod
    def _is_ipv4(ip):
        try:
            socket.inet_pton(socket.AF_INET, ip)
        except AttributeError:  # no inet_pton here, sorry
            try:
                socket.inet_aton(ip)
            except socket.error:
                return False
            return ip.count('.') == 3
        except socket.error:  # not a valid address
            return False
        return True

    def get_facts(self):
        state = self.device.monitor('web-ui', 'state')
        return {
            'uptime': int(state['results']['utc_last_reboot'] / 1000),
            'vendor': state['results']['model_name'],
            'os_version': '{} build {}'.format(state['version'], state['build']),
            'serial_number': state['serial'],
            'model': '{} - {}'.format(state['results']['model_number'], state['results']['model']),
            'hostname': state['results']['hostname'],
            'fqdn': state['results']['hostname'],
            'interface_list': list(self.device.monitor('system/interface', 'select')['results'].keys()),
        }

    def get_firewall_policies(self):
        params = {'exclude-default-values': 1}
        if self.vdom is None:
            params['global'] = 1
        policies_fg_stats = self.device.monitor('firewall', 'policy', vdom=self.vdom, parameters=params)
        policies_stats = {}
        # make single vdom response compatible with global multiple vdom response
        if self.vdom is not None:
            policies_fg_stats = [policies_fg_stats]

        for policies_fg_vdom_stats in policies_fg_stats:
            for stats in policies_fg_vdom_stats['results']:
                policies_stats[stats['policyid']] = stats

        policies_fg = self.device.get('firewall', 'policy', vdom=self.vdom, parameters=params)
        position = 1
        # make single vdom response compatible with global multiple vdom response
        if self.vdom is not None:
            policies_fg = [policies_fg]
        firewall_policies = {}
        for policies_vdom in policies_fg:
            for policy_fg in policies_vdom['results']:
                log = ''
                packet_hits = 0
                byte_hits = 0
                if policy_fg['policyid'] in policies_stats:
                    packet_hits = policies_stats[policy_fg['policyid']]['software_packets']
                    byte_hits = policies_stats[policy_fg['policyid']]['software_bytes']

                name = policy_fg['policyid']
                if 'name' in policy_fg.keys():
                    name = policy_fg['name']

                if 'logtraffic' in policy_fg.keys():
                    log = policy_fg['logtraffic']

                firewall_policies['{}/{}'.format(policies_vdom['vdom'], name)] = [{
                    'position': position,
                    'packet_hits': packet_hits,
                    'byte_hits': byte_hits,
                    'id': '{}'.format(policy_fg['policyid']),
                    'enabled': True,
                    'schedule': policy_fg['schedule'],
                    'log': log,
                    'l3_src': ', '.join(list(map(lambda elem: elem['name'], policy_fg['srcaddr']))),
                    'l3_dst': ', '.join(list(map(lambda elem: elem['name'], policy_fg['dstaddr']))),
                    'service': ', '.join(list(map(lambda elem: elem['name'], policy_fg['service']))),
                    'src_zone': ', '.join(list(map(lambda elem: elem['name'], policy_fg['srcintf']))),
                    'dst_zone': ', '.join(list(map(lambda elem: elem['name'], policy_fg['dstintf']))),
                    'action': policy_fg['action'],
                }]
                position += 1
        return firewall_policies

    def get_config(self, retrieve="all", full=False, sanitized=False):
        """Implementation of get_config for FortiOS.
        Returns the running configuration as dictionary.
        The startup and candidate is always empty string.
        https://community.fortinet.com/t5/FortiGate/Technical-Tip-Get-backup-config-file-on-FortiGate-using-RestAPI/ta-p/202286
        """
        params = {
            'scope': 'global'
        }
        return {
            "running": self.device.download('system', 'config', vdom=self.vdom,mkey="backup", parameters=params).text,
            "startup": "",
            "candidate": ""
        }

    def get_environment(self):
        import subprocess,json
        p=meter_fortigate(self.hostname,self.community)
        enviro = json.loads(p)
        return enviro
