import uuid
import json
from functools import lru_cache

from flask import current_app

from api.utils import is_url


SEVERITY = {
        'Informational': 'Info',
        'Low': 'Low',
        'Medium': 'Medium',
        'High': 'High',
        'UnSpecified': 'Unknown'
    }


CTIM_SCHEMA_VERSION = {
    'schema_version': current_app.config['CTIM_SCHEMA_VERSION'],
}


class Mapping:
    def __init__(self, client, observable, count):
        self.client = client
        self.observable = observable
        self.count = count
        self.source = 'Microsoft Defender ATP'
        self.default_sighting = {
                'type': 'sighting',
                'confidence': 'High',
                'internal': True,
                'source': self.source,
                'sensor': 'endpoint',
                **CTIM_SCHEMA_VERSION
            }
        self.relations = []
        self._adv_hunting_url = current_app.config['ADVANCED_HUNTING_URL']

    @staticmethod
    def _observable_type4url(url):
        return 'url' if is_url(url) else 'domain'

    @lru_cache(maxsize=512)
    def _call_hashes(self, value):
        sha1 = sha256 = md5 = None

        url = self.client.format_url('files', value)
        res = self.client.call_api(url)[0]

        if res.get('sha1'):
            sha1 = res['sha1']

        if res.get('sha256'):
            sha256 = res['sha256']

        if res.get('md5'):
            md5 = res['md5']

        return sha1, sha256, md5

    @staticmethod
    def _add_relation(origin, relation, source, related):
        return {
            'origin': origin,
            'relation': relation,
            'source': source,
            'related': related
        }

    def _build_relations_network(self, event, origin):
        if event['RemoteUrl'] and event['RemoteIP']:
            self.relations.append(self._add_relation(
                origin=origin,
                relation='Resolved_To',
                source={'type': self._observable_type4url(event['RemoteUrl']),
                        'value': event['RemoteUrl']},
                related={'type': 'ip',
                         'value': event['RemoteIP']}
            ))

        if event['RemoteIP'] and event['LocalIP']:
            self.relations.append(self._add_relation(
                origin=origin,
                relation='Connect_To',
                source={'type': 'ip',
                        'value': event['RemoteIP']},
                related={'type': 'ip',
                         'value': event['LocalIP']}
            ))

        def _make_relations_with_hash(hash_type, event, origin):
            if event['RemoteUrl']:
                self.relations.append(self._add_relation(
                    origin=origin,
                    relation='Connect_To',
                    source={
                        'type': hash_type,
                        'value': event[f'InitiatingProcess{hash_type.upper()}']
                    },
                    related={
                        'type': self._observable_type4url(event['RemoteUrl']),
                        'value': event['RemoteUrl']
                    }
                ))

            if event['RemoteIP']:
                self.relations.append(self._add_relation(
                    origin=origin,
                    relation='Connect_To',
                    source={
                        'type': hash_type,
                        'value': event[
                            f'InitiatingProcess{hash_type.upper()}']},
                    related={'type': 'ip',
                             'value': event['RemoteIP']}
                ))
            self._make_2level_hash(hash_type, event, origin)

        if event['InitiatingProcessSHA1'] \
                and (not event['InitiatingProcessSHA256']
                     or not event['InitiatingProcessMD5']):
            _, sha256, md5 = self._call_hashes(event['InitiatingProcessSHA1'])
            event['InitiatingProcessSHA256'] = sha256
            event['InitiatingProcessMD5'] = md5

        elif event['InitiatingProcessSHA256'] \
                and (not event['InitiatingProcessSHA1']
                     or not event['InitiatingProcessMD5']):
            sha1, _, md5 = self._call_hashes(event['InitiatingProcessSHA256'])
            event['InitiatingProcessSHA1'] = sha1
            event['InitiatingProcessMD5'] = md5

        if event['InitiatingProcessSHA1']:
            _make_relations_with_hash('sha1', event, origin)

        if event['InitiatingProcessSHA256']:
            _make_relations_with_hash('sha256', event, origin)

        if event['InitiatingProcessMD5']:
            _make_relations_with_hash('md5', event, origin)

    def _build_relations_file(self, event, origin):

        def _get_hashes(event, prefix=None):
            key_sha1 = prefix + 'SHA1' if prefix else 'SHA1'
            key_sha256 = prefix + 'SHA256' if prefix else 'SHA256'
            key_md5 = prefix + 'MD5' if prefix else 'MD5'
            if event[key_sha1] \
                    and (not event[key_sha256]
                         or not event[key_md5]):
                _, sha256, md5 = self._call_hashes(event[key_sha1])
                event[key_sha256] = sha256
                event[key_md5] = md5

            elif event[key_sha256] \
                    and (not event[key_sha1]
                         or not event[key_md5]):
                sha1, _, md5 = self._call_hashes(event[key_sha256])
                event[key_sha1] = sha1
                event[key_md5] = md5

            return event[key_sha1], event[key_sha256], event[key_md5]

        sha1, sha256, md5 = _get_hashes(event)
        if sha1:
            self._make_1level_hash('SHA1', event, origin)

        if sha256:
            self._make_1level_hash('SHA256', event, origin)

        if md5:
            self._make_1level_hash('MD5', event, origin)

        init_sha1, init_sha256, init_md5 = _get_hashes(
            event, prefix='InitiatingProcess')
        if init_sha1:
            self._make_2level_hash('SHA1', event, origin)

        if init_sha256:
            self._make_2level_hash('SHA256', event, origin)

        if init_md5:
            self._make_2level_hash('MD5', event, origin)

        if sha1 and init_sha1:
            self.relations.append(self._add_relation(
                origin=origin,
                relation='Parent_Of',
                source={'type': 'sha1',
                        'value': sha1},
                related={'type': 'sha1',
                         'value': init_sha1}
            ))

        if sha1 and init_sha256:
            self.relations.append(self._add_relation(
                origin=origin,
                relation='Parent_Of',
                source={'type': 'sha1',
                        'value': sha1},
                related={'type': 'sha256',
                         'value': init_sha256}
            ))

        if sha1 and init_md5:
            self.relations.append(self._add_relation(
                origin=origin,
                relation='Parent_Of',
                source={'type': 'sha1',
                        'value': sha1},
                related={'type': 'md5',
                         'value': init_md5}
            ))

        if sha256 and init_sha1:
            self.relations.append(self._add_relation(
                origin=origin,
                relation='Parent_Of',
                source={'type': 'sha256',
                        'value': sha256},
                related={'type': 'sha1',
                         'value': init_sha1}
            ))

        if sha256 and init_sha256:
            self.relations.append(self._add_relation(
                origin=origin,
                relation='Parent_Of',
                source={'type': 'sha256',
                        'value': sha256},
                related={'type': 'sha256',
                         'value': init_sha256}
            ))

        if sha256 and init_md5:
            self.relations.append(self._add_relation(
                origin=origin,
                relation='Parent_Of',
                source={'type': 'sha256',
                        'value': sha256},
                related={'type': 'md5',
                         'value': init_md5}
            ))

        if md5 and init_sha1:
            self.relations.append(self._add_relation(
                origin=origin,
                relation='Parent_Of',
                source={'type': 'md5',
                        'value': md5},
                related={'type': 'sha1',
                         'value': init_sha1}
            ))

        if md5 and init_sha256:
            self.relations.append(self._add_relation(
                origin=origin,
                relation='Parent_Of',
                source={'type': 'md5',
                        'value': md5},
                related={'type': 'sha256',
                         'value': init_sha256}
            ))

        if md5 and init_md5:
            self.relations.append(self._add_relation(
                origin=origin,
                relation='Parent_Of',
                source={'type': 'md5',
                        'value': md5},
                related={'type': 'md5',
                         'value': init_md5}
            ))

        if event['ActionType'] == 'FileRenamed':
            if event.get('PreviousFileName'):
                self.relations.append(self._add_relation(
                    origin=origin,
                    relation='Renamed_To',
                    source={'type': 'file_name',
                            'value': event['PreviousFileName']},
                    related={'type': 'file_name',
                             'value': event['FileName']}
                ))

    def _make_1level_hash(self, type_hash, event, origin):
        lower_th = type_hash.lower()

        file_name = event['fileName'] if event.get('fileName') \
            else event.get('FileName')
        if file_name:
            self.relations.append(self._add_relation(
                origin=origin,
                relation='File_Name_Of',
                source={'type': 'file_name',
                        'value': file_name},
                related={'type': lower_th,
                         'value': event[type_hash]}
            ))

        file_path = event['filePath'] if event.get('filePath') \
            else event.get('FolderPath')
        if file_path:
            self.relations.append(self._add_relation(
                origin=origin,
                relation='File_Path_Of',
                source={'type': 'file_path',
                        'value': file_path},
                related={'type': lower_th,
                         'value': event[type_hash]}
            ))

        if event.get('FileOriginUrl'):
            self.relations.append(self._add_relation(
                origin=origin,
                relation='Downloaded_From',
                source={'type': 'url',
                        'value': event['FileOriginUrl']},
                related={'type': lower_th,
                         'value': event[type_hash]}
            ))
            if event.get('FileOriginReferrerUrl'):
                self.relations.append(self._add_relation(
                    origin=origin,
                    relation='Refers_To',
                    source={'type': 'url',
                            'value': event['FileOriginUrl']},
                    related={'type': 'url',
                             'value': event['FileOriginReferrerUrl']}
                ))

    def _make_2level_hash(self, type_hash, event, origin):
        upper_th = type_hash.upper()
        lower_th = type_hash.lower()
        if event['InitiatingProcessFileName']:
            self.relations.append(self._add_relation(
                origin=origin,
                relation='File_Name_Of',
                source={'type': 'file_name',
                        'value': event['InitiatingProcessFileName']},
                related={'type': lower_th,
                         'value': event[f'InitiatingProcess{upper_th}']}
            ))

            if event['InitiatingProcessParentFileName']:
                self.relations.append(self._add_relation(
                    origin=origin,
                    relation='Parent_Of',
                    source={'type': 'file_name',
                            'value': event['InitiatingProcessParentFileName']},
                    related={'type': lower_th,
                             'value': event[f'InitiatingProcess{upper_th}']}
                ))

        if event['InitiatingProcessFolderPath']:
            self.relations.append(self._add_relation(
                origin=origin,
                relation='File_Path_Of',
                source={'type': 'file_path',
                        'value': event['InitiatingProcessFolderPath']},
                related={'type': lower_th,
                         'value': event[f'InitiatingProcess{upper_th}']}
            ))

    @lru_cache(maxsize=512)
    def _get_os_info(self, device_id):
        """
        https://docs.microsoft.com/en-us/windows/security/threat-protection
        /microsoft-defender-atp/get-machine-by-id

        Queries information about a specific machine and
        gets the operating system.
        :param device_id:
        :return:
        """
        url = self.client.format_url('machines', device_id)
        res = self.client.call_api(url)[0]

        os = res['osPlatform']
        if res.get('osProcessor'):
            os += res['osProcessor']
        if res.get('version'):
            os = os + ' version: ' + res['version']
        return os

    @lru_cache(maxsize=512)
    def _get_network_info(self, device_id):
        """
        https://docs.microsoft.com/en-us/windows/security/threat-protection
        /microsoft-defender-atp/run-advanced-query-api

        Queries information about network interface for a specific machine.
        :param device_id: A device ID
        :return: <list> - A list of dictionaries consisting of MAC-addresses
        and IP(IPv6)s or empty list
        """

        observables = []

        query = "DeviceNetworkInfo " \
                "| where DeviceId == '{device_id}' " \
                "| summarize (LastTimestamp)=arg_max(Timestamp, ReportId) " \
                "by DeviceId, " \
                "NetworkAdapterType, " \
                "MacAddress, " \
                "DeviceName, " \
                "IPAddresses".format(device_id=device_id)

        query = json.dumps({'Query': query}).encode('utf-8')
        response, error = self.client.call_api(
            self._adv_hunting_url,
            'POST', data=query)

        if response and response.get('Results'):
            for item in response['Results']:
                observables.append(
                    {'type': 'mac_address', 'value': item['MacAddress']})

                for ips_info in json.loads(item['IPAddresses']):
                    if ':' in ips_info['IPAddress']:
                        observables.append(
                            {'type': 'ipv6', 'value': ips_info['IPAddress']}
                        )
                    elif '.' in ips_info['IPAddress']:
                        observables.append(
                            {'type': 'ip', 'value': ips_info['IPAddress']}
                        )
        return observables

    def _get_target_from_alert(self, alert):

        observables = [
            {'type': 'hostname', 'value': alert['computerDnsName']},
            {'type': 'ms_machine_id', 'value': alert['machineId']}
            # {'type': 'device', 'value': alert['machineId']}
        ]

        os = self._get_os_info(alert['machineId'])
        networks = self._get_network_info(alert['machineId'])
        if networks:
            observables.extend(networks)

        return {
            'type': 'endpoint',
            'os': os,
            'observables': observables,
            'observed_time': {
                'start_time': alert['firstEventTime'],
                'end_time': alert['firstEventTime']
            }
        }

    def _get_target_from_ah(self, event):

        observables = [
            {'type': 'hostname', 'value': event['DeviceName']},
            {'type': 'ms_machine_id', 'value': event['DeviceId']}
            # {'type': 'device', 'value': event['DeviceId']}
        ]

        os = self._get_os_info(event['DeviceId'])

        observables.append(
            {'type': 'mac_address', 'value': event['MacAddress']})

        for ips_info in json.loads(event['IPAddresses']):
            if ':' in ips_info['IPAddress']:
                observables.append(
                    {'type': 'ipv6', 'value': ips_info['IPAddress']}
                )
            elif '.' in ips_info['IPAddress']:
                observables.append(
                    {'type': 'ip', 'value': ips_info['IPAddress']}
                )

        return {
            'type': 'endpoint',
            'os': os,
            'observables': observables,
            'observed_time': {
                'start_time': event['Timestamp'],
                'end_time': event['Timestamp']
            }
        }

    @staticmethod
    def _get_details(event):
        columns = []
        rows = []

        if event.get('ActionType'):
            columns.append({'name': 'ActionType', 'type': 'string'})
            rows.append([event['ActionType']], )
        return {'columns': columns, 'rows': rows}

    def build_sighting_from_ah(self, event):
        sighting = self.default_sighting.copy()

        targets = []
        self.relations = []

        if self.observable['type'] in ('domain', 'ip'):
            self._build_relations_network(event, self.source)
        elif self.observable['type'] in ('sha1', 'sha256', 'md5'):
            self._build_relations_file(event, self.source)

        targets.append(self._get_target_from_ah(event))

        sighting['data'] = self._get_details(event)

        sighting['relations'] = self.relations

        sighting['targets'] = targets

        sighting['id'] = f'transient-sighting:{uuid.uuid4()}'
        sighting['count'] = self.count

        sighting['observables'] = [self.observable, ]

        sighting['observed_time'] = {
            'start_time': event['Timestamp'],
            'end_time': event['Timestamp']
        }

        return sighting

    def build_sighting_from_alert(self, alert):
        sighting = self.default_sighting.copy()

        targets = []
        self.relations = []

        if alert['computerDnsName']:
            targets.append(self._get_target_from_alert(alert))

        sha1 = None
        sha256 = None
        md5 = None
        ip = None
        url = None
        url_type = None

        for evidence in alert['evidence']:
            if evidence.get('entityType') in ('Process', 'File'):

                if evidence.get('sha1') and evidence.get('sha256') \
                        and evidence.get('md5'):
                    sha1 = evidence['sha1']
                    sha256 = evidence['sha256']
                    md5 = evidence['md5']
                else:
                    if evidence.get('sha1') \
                            and (not evidence.get('sha256')
                                 or not evidence.get('md5')):
                        sha1 = evidence['sha1']
                        _, sha256, md5 = self._call_hashes(sha1)

                    elif evidence.get('sha256') \
                            and (not evidence.get('sha1')
                                 or not evidence.get('md5')):
                        sha256 = evidence['sha256']
                        sha1, _, md5 = self._call_hashes(sha256)

                    evidence['sha1'] = sha1
                    evidence['sha256'] = sha256
                    evidence['md5'] = md5

                if sha1:
                    self._make_1level_hash(
                        'sha1',
                        evidence,
                        alert['detectionSource']
                    )
                if sha256:
                    self._make_1level_hash(
                        'sha256',
                        evidence,
                        alert['detectionSource']
                    )
                if md5:
                    self._make_1level_hash(
                        'md5',
                        evidence,
                        alert['detectionSource']
                    )

                if evidence.get('parentProcessId'):
                    for e in alert['evidence']:
                        if e['processId'] == evidence['parentProcessId']:
                            if sha1 and e.get('sha1'):
                                self.relations.append(
                                    self._add_relation(
                                        origin=alert['detectionSource'],
                                        relation='Injected_Into',
                                        source={'value': sha1,
                                                'type': 'sha1'},
                                        related={'value': e['sha1'],
                                                 'type': 'sha1'}
                                    )
                                )
                            if sha1 and e.get('sha256'):
                                self.relations.append(
                                    self._add_relation(
                                        origin=alert['detectionSource'],
                                        relation='Injected_Into',
                                        source={'value': sha1,
                                                'type': 'sha1'},
                                        related={'value': e['sha256'],
                                                 'type': 'sha256'}
                                    )
                                )
                            if sha256 and e.get('sha1'):
                                self.relations.append(
                                    self._add_relation(
                                        origin=alert['detectionSource'],
                                        relation='Injected_Into',
                                        source={'value': sha256,
                                                'type': 'sha256'},
                                        related={'value': e['sha1'],
                                                 'type': 'sha1'}
                                    )
                                )
                            if sha256 and e.get('sha256'):
                                self.relations.append(
                                    self._add_relation(
                                        origin=alert['detectionSource'],
                                        relation='Injected_Into',
                                        source={'value': sha256,
                                                'type': 'sha256'},
                                        related={'value': e['sha256'],
                                                 'type': 'sha256'}
                                    )
                                )

            if evidence.get('entityType') == 'Ip':
                ip = evidence.get('ipAddress')

            if evidence.get('entityType') == 'Url':
                url = evidence.get('url')
                url_type = self._observable_type4url(url)

            def _make_relations_with_hash(hash_type, hash_value,
                                          ip_address, url_address,
                                          url_type=None):
                if url_address:
                    self.relations.append(self._add_relation(
                        origin=alert['detectionSource'],
                        relation='Connect_To',
                        source={'type': hash_type,
                                'value': hash_value},
                        related={'type': url_type,
                                 'value': url_address}
                    ))

                if ip_address:
                    self.relations.append(self._add_relation(
                        origin=alert['detectionSource'],
                        relation='Connect_To',
                        source={'type': hash_type,
                                'value': hash_value},
                        related={'type': 'ip',
                                 'value': ip_address}
                    ))

            if url and ip:
                self.relations.append(self._add_relation(
                    origin=alert['detectionSource'],
                    relation='Resolved_To',
                    source={'type': url_type,
                            'value': url},
                    related={'type': 'ip',
                             'value': ip}
                ))

            if sha1:
                _make_relations_with_hash('sha1', sha1, ip,
                                          url, url_type)
            if sha256:
                _make_relations_with_hash('sha256', sha256, ip,
                                          url, url_type)
            if md5:
                _make_relations_with_hash('md5', md5, ip,
                                          url, url_type)

        sighting['targets'] = targets
        sighting['relations'] = self.relations

        sighting['id'] = f'transient-sighting:{uuid.uuid4()}'
        sighting['count'] = self.count
        sighting['observables'] = [self.observable, ]
        sighting['observed_time'] = {
            'start_time': alert['firstEventTime'],
            'end_time': alert['firstEventTime']
        }
        sighting['title'] = alert['title']
        sighting['description'] = alert['description']
        sighting['severity'] = SEVERITY.get(alert['severity'], None)
        sighting['timestamp'] = alert['lastUpdateTime']
        sighting['source_uri'] = \
            'https://securitycenter.windows.com/alerts' \
            '/{alert_id}/details'.format(alert_id=alert['id'])

        return sighting
