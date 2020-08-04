import uuid
import json

from flask import current_app


SEVERITY = {
        'Informational': 'Info',
        'Low': 'Low',
        'Medium': 'Medium',
        'High': 'High',
        'UnSpecified': 'Unknown'
    }


CTIM_SCHEMA_VERSION = {
    'schema_version': '1.0.17',
}


class Mapping:
    def __init__(self, client, observable, count, entity):
        self.client = client
        self.observable = observable
        self.count = count
        self.entity = entity
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

    def _get_hash(self, value):
        url = self.client.format_url('files', value)
        res = self.client.call_api(url)[0]
        return res

    @staticmethod
    def _add_relation(origin, relation, source, related):
        return {
            'origin': origin,
            'relation': relation,
            'source': source,
            'related': related
        }

    def _build_relations_network(self, event, origin):
        if event['InitiatingProcessSHA1'] and event['RemoteUrl']:
            self.relations.append(self._add_relation(
                origin=origin,
                relation='Connect_To',
                source={'type': 'domain',
                        'value': event['RemoteUrl']},
                related={'type': 'sha1',
                         'value': event['InitiatingProcessSHA1']}
            ))

            self._make_2level_hash('sha1', event, origin)

            if event['InitiatingProcessSHA256']:
                self.relations.append(self._add_relation(
                    origin=origin,
                    relation='Connect_To',
                    source={'type': 'domain',
                            'value': event['RemoteUrl']},
                    related={'type': 'sha1',
                             'value': event['InitiatingProcessSHA256']}
                ))

                self._make_2level_hash('sha256', event, origin)
            else:
                sha = self._get_hash(event['InitiatingProcessSHA1'])
                if sha and sha.get('sha256'):
                    event['InitiatingProcessSHA256'] = sha['sha256']
                    self.relations.append(self._add_relation(
                        origin=origin,
                        relation='Connect_To',
                        source={'type': 'domain',
                                'value': event['RemoteUrl']},
                        related={'type': 'sha1',
                                 'value': event['InitiatingProcessSHA256']}
                    ))

                    self._make_2level_hash('sha256', event, origin)

            if event['InitiatingProcessMD5']:
                self.relations.append(self._add_relation(
                    origin=origin,
                    relation='Connect_To',
                    source={'type': 'domain',
                            'value': event['RemoteUrl']},
                    related={'type': 'sha1',
                             'value': event['InitiatingProcessMD5']}
                ))

                self._make_2level_hash('md5', event, origin)
            else:
                md5 = self._get_hash(event['InitiatingProcessSHA1'])
                if md5 and md5.get('md5'):
                    event['InitiatingProcessMD5'] = md5['md5']
                    self.relations.append(self._add_relation(
                        origin=origin,
                        relation='Connect_To',
                        source={'type': 'domain',
                                'value': event['RemoteUrl']},
                        related={'type': 'sha1',
                                 'value': event['InitiatingProcessMD5']}
                    ))

                    self._make_2level_hash('md5', event, origin)

        if event['RemoteUrl']:
            if event['RemoteIP']:
                self.relations.append(self._add_relation(
                    origin=origin,
                    relation='Resolved_To',
                    source={'type': 'domain',
                            'value': event['RemoteUrl']},
                    related={'type': 'ip',
                             'value': event['RemoteIP']}
                ))

    def _build_relations_file(self, event, origin):
        if event['SHA1']:
            self._make_1level_hash('SHA1', event, origin)

        if event['SHA256']:
            self._make_1level_hash('SHA256', event, origin)
        else:
            sha = self._get_hash(event['SHA1'])
            if sha and sha.get('sha256'):
                event['SHA256'] = sha['sha256']
                self._make_1level_hash('SHA256', event, origin)

        if event['MD5']:
            self._make_1level_hash('MD5', event, origin)
        else:
            md5 = self._get_hash(event['SHA1'])
            if md5 and md5.get('md5'):
                event['MD5'] = md5['md5']
                self._make_1level_hash('MD5', event, origin)

        if event['InitiatingProcessSHA1']:
            self._make_2level_hash('SHA1', event, origin)

        if event['InitiatingProcessSHA256']:
            self._make_2level_hash('SHA256', event, origin)
        else:
            sha = self._get_hash(event['InitiatingProcessSHA1'])
            if sha and sha.get('sha256'):
                event['InitiatingProcessSHA256'] = sha['sha256']
                self._make_2level_hash('SHA256', event, origin)

        if event['InitiatingProcessMD5']:
            self._make_2level_hash('MD5', event, origin)
        else:
            md5 = self._get_hash(event['SHA1'])
            if md5 and md5.get('md5'):
                event['InitiatingProcessMD5'] = md5['md5']
                self._make_2level_hash('MD5', event, origin)

        if event['SHA1'] and event['InitiatingProcessSHA1']:
            self.relations.append(self._add_relation(
                origin=origin,
                relation='Parent_Of',
                source={'type': 'sha1',
                        'value': event['SHA1']},
                related={'type': 'sha1',
                         'value': event['InitiatingProcessSHA1']}
            ))

        if event['SHA1'] and event['InitiatingProcessSHA256']:
            self.relations.append(self._add_relation(
                origin=origin,
                relation='Parent_Of',
                source={'type': 'sha1',
                        'value': event['SHA1']},
                related={'type': 'sha256',
                         'value': event['InitiatingProcessSHA256']}
            ))

        if event['SHA1'] and event['InitiatingProcessMD5']:
            self.relations.append(self._add_relation(
                origin=origin,
                relation='Parent_Of',
                source={'type': 'sha1',
                        'value': event['SHA1']},
                related={'type': 'md5',
                         'value': event['InitiatingProcessMD5']}
            ))

        if event['SHA256'] and event['InitiatingProcessSHA1']:
            self.relations.append(self._add_relation(
                origin=origin,
                relation='Parent_Of',
                source={'type': 'sha256',
                        'value': event['SHA256']},
                related={'type': 'sha1',
                         'value': event['InitiatingProcessSHA1']}
            ))

        if event['SHA256'] and event['InitiatingProcessSHA256']:
            self.relations.append(self._add_relation(
                origin=origin,
                relation='Parent_Of',
                source={'type': 'sha256',
                        'value': event['SHA256']},
                related={'type': 'sha256',
                         'value': event['InitiatingProcessSHA256']}
            ))

        if event['SHA256'] and event['InitiatingProcessMD5']:
            self.relations.append(self._add_relation(
                origin=origin,
                relation='Parent_Of',
                source={'type': 'sha256',
                        'value': event['SHA256']},
                related={'type': 'md5',
                         'value': event['InitiatingProcessMD5']}
            ))

        if event['MD5'] and event['InitiatingProcessSHA1']:
            self.relations.append(self._add_relation(
                origin=origin,
                relation='Parent_Of',
                source={'type': 'md5',
                        'value': event['MD5']},
                related={'type': 'sha1',
                         'value': event['InitiatingProcessSHA1']}
            ))

        if event['MD5'] and event['InitiatingProcessSHA256']:
            self.relations.append(self._add_relation(
                origin=origin,
                relation='Parent_Of',
                source={'type': 'md5',
                        'value': event['MD5']},
                related={'type': 'sha256',
                         'value': event['InitiatingProcessSHA256']}
            ))

        if event['MD5'] and event['InitiatingProcessMD5']:
            self.relations.append(self._add_relation(
                origin=origin,
                relation='Parent_Of',
                source={'type': 'md5',
                        'value': event['MD5']},
                related={'type': 'md5',
                         'value': event['InitiatingProcessMD5']}
            ))

        if event['FileOriginUrl']:
            self.relations.append(self._add_relation(
                origin=origin,
                relation='Downloaded_From',
                source={'type': 'url',
                        'value': event['FileOriginUrl']},
                related={'type': 'file_name',
                         'value': event['FileName']}
            ))
        if event['FileOriginReferrerUrl']:
            self.relations.append(self._add_relation(
                origin=origin,
                relation='Refers_To',
                source={'type': 'url',
                        'value': event['FileOriginUrl']},
                related={'type': 'url',
                         'value': event['FileOriginReferrerUrl']}
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
        if event['InitiatingProcessFolderPath']:
            self.relations.append(self._add_relation(
                origin=origin,
                relation='File_Path_Of',
                source={'type': 'file_path',
                        'value': event['InitiatingProcessFolderPath']},
                related={'type': lower_th,
                         'value': event[f'InitiatingProcess{upper_th}']}
            ))
        if event['InitiatingProcessParentFileName']:
            self.relations.append(self._add_relation(
                origin=origin,
                relation='Child_Of',
                source={'type': 'file_name',
                        'value': event['InitiatingProcessParentFileName']},
                related={'type': lower_th,
                         'value': event[f'InitiatingProcess{upper_th}']}
            ))

    def _get_target_from_alert(self, alert):
        url = self.client.format_url('machines', alert['machineId'])
        res = self.client.call_api(url)[0]

        observables = [
            {'type': 'hostname', 'value': alert['computerDnsName']},
            {'type': 'ip', 'value': res['lastIpAddress']}
        ]

        return {
            'type': 'endpoint',
            'os': res['osPlatform'],
            'observables': observables,
            'observed_time': {
                'start_time': alert['firstEventTime'],
                'end_time': alert['firstEventTime']
            }
        }

    def _get_target_from_ah(self, event):
        url = self.client.format_url('machines', event['DeviceId'])
        res = self.client.call_api(url)[0]

        observables = [
            {'type': 'hostname', 'value': event['DeviceName']},
            {'type': 'ip', 'value': res['lastIpAddress']}
        ]

        query = "DeviceNetworkInfo " \
                "| where DeviceId == '{device_id}' " \
                "| summarize (LastTimestamp)=arg_max(Timestamp, ReportId) " \
                "by DeviceId, " \
                "NetworkAdapterType, " \
                "MacAddress, " \
                "DeviceName, " \
                "IPAddresses".format(device_id=event['DeviceId'])

        query = json.dumps({'Query': query}).encode('utf-8')
        result, error = self.client.call_api(
            current_app.config['ADVANCED_HUNTING_URL'],
            'POST', query)

        if result and result.get('Results'):
            for item in result['Results']:
                observables.append(
                    {'type': 'mac_address', 'value': item['MacAddress']})

        return {
            'type': 'endpoint',
            'os': res['osPlatform'],
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

        for evidence in alert['evidence']:

            if evidence.get('parentProcessId'):
                for e in alert['evidence']:
                    if e['processId'] == evidence['parentProcessId']:
                        self.relations.append(
                            self._add_relation(
                                origin=alert['detectionSource'],
                                relation='Injected_Into',
                                source={'value': evidence['fileName'],
                                        'type': 'file_name'},
                                related={'value': e['fileName'],
                                         'type': 'file_name'}
                            )
                        )

            if evidence['sha1']:
                self._make_1level_hash(
                    'sha1',
                    evidence,
                    alert['detectionSource']
                )
                if not evidence.get('sha256'):
                    sha = self._get_hash(evidence['sha1'])
                    if sha and sha.get('sha256'):
                        evidence['sha256'] = sha['sha256']
                        self._make_1level_hash(
                            'sha256',
                            evidence,
                            alert['detectionSource']
                        )
                else:
                    self._make_1level_hash(
                        'sha256',
                        evidence,
                        alert['detectionSource']
                    )
                if not evidence.get('md5'):
                    md5 = self._get_hash(evidence['sha1'])
                    if md5 and md5.get('md5'):
                        evidence['md5'] = md5['md5']
                        self._make_1level_hash(
                            'md5',
                            evidence,
                            alert['detectionSource']
                        )
                else:
                    self._make_1level_hash(
                        'md5',
                        evidence,
                        alert['detectionSource']
                    )

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
        sighting['source_uri'] = 'https://securitycenter.windows.com/' \
                                 '{entity}/' \
                                 '{o_value}/' \
                                 'alerts'.format(entity=self.entity,
                                                 o_value=self.observable[
                                                     'value'])

        return sighting
