import uuid


SEVERITY = {
        'Informational': 'Info',
        'Low': 'Low',
        'Medium': 'Medium',
        'High': 'High',
        'UnSpecified': 'Unknown'
    }


CTIM_SCHEMA_VERSION = {
    'schema_version': '1.0.16',
}


def _get_target_from_alert(client, alert):
    url = client.format_url('machines', alert['machineId'])
    res = client.call_api(url)

    observables = [
        {'type': 'hostname', 'value': alert['computerDnsName']},
        {'type': 'ip', 'value': res['lastIpAddress']}
    ]

    if alert['relatedUser'] and alert['relatedUser'].get('userName'):
        observables.append(
            {'type': 'user', 'value': alert['relatedUser']['userName']})

    return {
        'type': 'endpoint',
        'os': res['osPlatform'],
        'observables': observables,
        'observed_time': {
            'start_time': alert['firstEventTime']
        }
    }


def _get_target_from_ah(client, event):
    url = client.format_url('machines', event['DeviceId'])
    res = client.call_api(url)

    observables = [
        {'type': 'hostname', 'value': event['DeviceName']},
        {'type': 'ip', 'value': res['lastIpAddress']}
    ]

    return {
        'type': 'endpoint',
        'os': res['osPlatform'],
        'observables': observables,
        'observed_time': {
            'start_time': event['Timestamp']
        }
    }


def _add_relation(origin, relation, source, related):
    return {
        'origin': origin,
        'relation': relation,
        'source': source,
        'related': related
    }


def get_sightings_from_alert(client, alert, observable, count, entity):
    sighting = {
        'type': 'sighting',
        'confidence': 'High',
        'internal': True,
        'source': 'Microsoft Defender ATP',
        'sensor': 'endpoint',
        **CTIM_SCHEMA_VERSION
    }

    targets = []
    relations = []

    if alert['computerDnsName']:
        targets.append(_get_target_from_alert(client, alert))

    for evidence in alert['evidence']:
        def _related_sha1(value):
            return {'value': value, 'type': 'sha1'}

        def _related_sha256(value):
            return {'value': value, 'type': 'sha256'}

        if evidence.get('parentProcessId'):
            for e in alert['evidence']:
                if e['processId'] == evidence['parentProcessId']:
                    relations.append(
                        _add_relation(
                            alert['detectionSource'],
                            'Injected_Into',
                            {'value': evidence['fileName'],
                             'type': 'file_name'},
                            {'value': e['fileName'],
                             'type': 'file_name'}
                        )
                    )

        if evidence.get('fileName'):
            if evidence.get('sha1'):
                relations.append(
                    _add_relation(
                        alert['detectionSource'],
                        'File_Name_Of',
                        {'value': evidence['fileName'],
                         'type': 'file_name'},
                        _related_sha1(evidence['sha1'])
                    )
                )

            if evidence.get('sha256'):
                relations.append(
                    _add_relation(
                        alert['detectionSource'],
                        'File_Name_Of',
                        {'value': evidence['fileName'],
                         'type': 'file_name'},
                        _related_sha256(evidence['sha256'])
                    )
                )

        if evidence.get('filePath'):
            if evidence.get('sha1'):
                relations.append(
                    _add_relation(
                        alert['detectionSource'],
                        'File_Path_Of',
                        {'value': evidence['filePath'],
                         'type': 'file_path'},
                        _related_sha1(evidence['sha1'])
                    )
                )

            if evidence.get('sha256'):
                relations.append(
                    _add_relation(
                        alert['detectionSource'],
                        'File_Path_Of',
                        {'value': evidence['filePath'],
                         'type': 'file_path'},
                        _related_sha256(evidence['sha256'])
                    )
                )

    sighting['targets'] = targets
    sighting['relations'] = relations

    sighting['id'] = f'transient-sighting:{uuid.uuid4()}'
    sighting['count'] = count
    sighting['observables'] = [observable, ]
    sighting['observed_time'] = {'start_time': alert['firstEventTime']}
    sighting['title'] = alert['title']
    sighting['description'] = alert['description']
    sighting['severity'] = SEVERITY.get(alert['severity'], None)
    sighting['timestamp'] = alert['lastUpdateTime']
    sighting['source_uri'] = 'https://securitycenter.windows.com/' \
                             '{entity}/' \
                             '{o_value}/' \
                             'alerts'.format(entity=entity,
                                             o_value=observable['value'])
    return sighting


def _get_domain(event, client):
    origin = 'Microsoft Defender ATP'
    relations = []

    if event['RemoteIP'] and event['RemoteUrl']:
        relations.append(_add_relation(
            origin=origin,
            relation='Resolved_To',
            source={'type': 'ip', 'value': event['RemoteIP']},
            related={'type': 'domain',
                     'value': event['RemoteUrl']}
        ))
        if event['LocalIP']:
            relations.append(_add_relation(
                origin=origin,
                relation='Connected_To',
                source={'type': 'ip',
                        'value': event['LocalIP']},
                related={'type': 'ip',
                         'value': event['RemoteIP']}
            ))
        if event['InitiatingProcessFileName']:
            relations.append(_add_relation(
                origin=origin,
                relation='Connected_To',
                source={'type': 'file_name',
                        'value': event[
                            'InitiatingProcessFileName']},
                related={'type': 'ip',
                         'value': event['RemoteIP']}
            ))
            if event['InitiatingProcessSHA1']:
                relations.append(_add_relation(
                    origin=origin,
                    relation='File_Name_Of',
                    source={'type': 'file_name',
                            'value': event[
                                'InitiatingProcessFileName']},
                    related={'type': 'sha1', 'value': event[
                        'InitiatingProcessSHA1']}
                ))
            if event['InitiatingProcessSHA256']:
                relations.append(_add_relation(
                    origin=origin,
                    relation='File_Name_Of',
                    source={'type': 'file_name',
                            'value': event[
                                'InitiatingProcessFileName']},
                    related={'type': 'sha256',
                             'value': event['InitiatingProcessSHA256']}
                ))
            else:
                url = client.format_url(
                    'files', event['InitiatingProcessSHA1'])
                res = client.call_api(url)
                if res is not None:
                    relations.append(_add_relation(
                        origin=origin,
                        relation='File_Name_Of',
                        source={'type': 'file_name',
                                'value': event[
                                    'InitiatingProcessFileName']},
                        related={'type': 'sha256', 'value': res['sha256']}
                    ))
            if event['InitiatingProcessMD5']:
                relations.append(_add_relation(
                    origin=origin,
                    relation='File_Name_Of',
                    source={'type': 'file_name',
                            'value': event[
                                'InitiatingProcessFileName']},
                    related={'type': 'md5',
                             'value': event[
                                 'InitiatingProcessMD5']}
                ))
            if event['InitiatingProcessFolderPath']:
                relations.append(_add_relation(
                    origin=origin,
                    relation='File_Path_Of',
                    source={'type': 'file_path',
                            'value': event[
                                'InitiatingProcessFolderPath']},
                    related={'type': 'sha1',
                             'value': event[
                                 'InitiatingProcessSHA1']}
                ))
            if event['InitiatingProcessParentFileName']:
                relations.append(_add_relation(
                    origin=origin,
                    relation='Related_To',
                    source={'type': 'file_name',
                            'value': event[
                                'InitiatingProcessFileName']},
                    related={
                        'type': 'file_name',
                        'value': event[
                            'InitiatingProcessParentFileName']}
                ))
    return relations


def _get_ip(event, client):
    origin = 'Microsoft Defender ATP'
    relations = []
    if event['RemoteIP']:
        if event['RemoteUrl']:
            relations.append(_add_relation(
                origin=origin,
                relation='Resolved_To',
                source={'type': 'ip',
                        'value': event['RemoteIP']},
                related={'type': 'domain',
                         'value': event[
                             'RemoteUrl']}
            ))
        if event['LocalIP']:
            relations.append(_add_relation(
                origin=origin,
                relation='Connected_To',
                source={'type': 'ip',
                        'value': event['LocalIP']},
                related={'type': 'ip',
                         'value': event['RemoteIP']}
            ))
        if event['InitiatingProcessParentFileName']:
            relations.append(_add_relation(
                origin=origin,
                relation='Related_To',
                source={'type': 'file_name',
                        'value': event[
                            'InitiatingProcessFileName']},
                related={'type': 'ip', 'value': event['RemoteIP']}
            ))
            if event['InitiatingProcessSHA1']:
                relations.append(_add_relation(
                    origin=origin,
                    relation='File_Name_Of',
                    source={'type': 'file_name',
                            'value': event[
                                'InitiatingProcessFileName']},
                    related={'type': 'sha1', 'value': event[
                        'InitiatingProcessSHA1']}
                ))
            if event['InitiatingProcessSHA256']:
                relations.append(_add_relation(
                    origin=origin,
                    relation='File_Name_Of',
                    source={'type': 'file_name',
                            'value': event[
                                'InitiatingProcessFileName']},
                    related={'type': 'sha256', 'value': event[
                        'InitiatingProcessSHA256']}
                ))
            else:
                url = client.format_url(
                    'files', event['InitiatingProcessSHA1'])
                res = client.call_api(url)
                if res is not None:
                    relations.append(_add_relation(
                        origin=origin,
                        relation='File_Name_Of',
                        source={'type': 'file_name',
                                'value': event[
                                    'InitiatingProcessFileName']},
                        related={'type': 'sha256', 'value': res['sha256']}
                    ))
            if event['InitiatingProcessMD5']:
                relations.append(_add_relation(
                    origin=origin,
                    relation='File_Name_Of',
                    source={'type': 'file_name',
                            'value': event[
                                'InitiatingProcessFileName']},
                    related={'type': 'sha1', 'value': event[
                        'InitiatingProcessMD5']}
                ))
            if event['InitiatingProcessFolderPath']:
                relations.append(_add_relation(
                    origin=origin,
                    relation='File_Path_Of',
                    source={'type': 'file_path',
                            'value': event[
                                'InitiatingProcessFolderPath']},
                    related={'type': 'file_name', 'value': event[
                        'InitiatingProcessParentFileName']}
                ))

        if event['InitiatingProcessParentFileName']:
            relations.append(_add_relation(
                origin=origin,
                relation='Related_To',
                source={'type': 'file_name',
                        'value': event[
                            'InitiatingProcessParentFileName']},
                related={'type': 'ip', 'value': event['RemoteIP']}
            ))

        if event['InitiatingProcessAccountName']:
            relations.append(_add_relation(
                origin=origin,
                relation='Used',
                source={'type': 'user',
                        'value': event[
                            'InitiatingProcessAccountName']},
                related={'type': 'ip', 'value': event['RemoteIP']}
            ))
    return relations


def _get_file(event, client):
    origin = 'Microsoft Defender ATP'
    relations = []
    if event['FileName']:
        if event['SHA1']:
            relations.append(_add_relation(
                origin=origin,
                relation='File_Name_Of',
                source={'type': 'file_name',
                        'value': event['FileName']},
                related={'type': 'sha1',
                         'value': event['SHA1']}
            ))
        if event['SHA256']:
            relations.append(_add_relation(
                origin=origin,
                relation='File_Name_Of',
                source={'type': 'file_name',
                        'value': event['FileName']},
                related={'type': 'sha256',
                         'value': event['SHA256']}
            ))
        else:
            url = client.format_url(
                'files', event['SHA1'])
            res = client.call_api(url)
            if res is not None:
                relations.append(_add_relation(
                    origin=origin,
                    relation='File_Name_Of',
                    source={'type': 'file_name',
                            'value': event['FileName']},
                    related={'type': 'sha256', 'value': res['sha256']}
                ))
        if event['MD5']:
            relations.append(_add_relation(
                origin=origin,
                relation='File_Name_Of',
                source={'type': 'file_name',
                        'value': event['FileName']},
                related={'type': 'md5',
                         'value': event['MD5']}
            ))
        if event['FolderPath']:
            relations.append(_add_relation(
                origin=origin,
                relation='File_Path_Of',
                source={'type': 'file_path',
                        'value': event['FolderPath']},
                related={'type': 'file_name',
                         'value': event['FileName']}
            ))
        if event['FileOriginUrl']:
            relations.append(_add_relation(
                origin=origin,
                relation='Uploaded_From',
                source={'type': 'url',
                        'value': event['FileOriginUrl']},
                related={'type': 'file_name',
                         'value': event['FileName']}
            ))
        if event['FileOriginReferrerUrl']:
            relations.append(_add_relation(
                origin=origin,
                relation='Uploaded_From',
                source={'type': 'url',
                        'value': event['FileOriginUrl']},
                related={'type': 'file_name',
                         'value': event['FileName']}
            ))
        if event['InitiatingProcessFileName']:
            relations.append(_add_relation(
                origin=origin,
                relation='Related_To',
                source={'type': 'file_name',
                        'value': event[
                            'InitiatingProcessFileName']},
                related={'type': 'file_name',
                         'value': event['FileName']}
            ))

            if event['InitiatingProcessSHA1']:
                relations.append(_add_relation(
                    origin=origin,
                    relation='File_Name_Of',
                    source={'type': 'file_name',
                            'value': event[
                                'InitiatingProcessFileName']},
                    related={'type': 'sha1', 'value': event[
                        'InitiatingProcessSHA1']}
                ))
            if event['SHA256']:
                relations.append(_add_relation(
                    origin=origin,
                    relation='File_Name_Of',
                    source={'type': 'file_name',
                            'value': event[
                                'InitiatingProcessFileName']},
                    related={'type': 'sha256',
                             'value': event['SHA256']}
                ))
            else:
                url = client.format_url(
                    'files', event['InitiatingProcessSHA1'])
                res = client.call_api(url)
                if res is not None:
                    relations.append(_add_relation(
                        origin=origin,
                        relation='File_Name_Of',
                        source={'type': 'file_name',
                                'value': event[
                                    'InitiatingProcessFileName']},
                        related={'type': 'sha256', 'value': res['sha256']}
                    ))
            if event['InitiatingProcessMD5']:
                relations.append(_add_relation(
                    origin=origin,
                    relation='File_Name_Of',
                    source={'type': 'file_name',
                            'value': event[
                                'InitiatingProcessFileName']},
                    related={'type': 'md5',
                             'value': event[
                                 'InitiatingProcessMD5']}
                ))
            if event['InitiatingProcessFolderPath']:
                relations.append(_add_relation(
                    origin=origin,
                    relation='File_Path_Of',
                    source={'type': 'file_path',
                            'value': event[
                                'InitiatingProcessFolderPath']},
                    related={'type': 'file_name',
                             'value': event[
                                 'InitiatingProcessFileName']}
                ))
            if event['InitiatingProcessParentFileName']:
                relations.append(_add_relation(
                    origin=origin,
                    relation='Related_To',
                    source={'type': 'file_name',
                            'value': event[
                                'InitiatingProcessFileName']},
                    related={
                        'type': 'file_name',
                        'value': event[
                            'InitiatingProcessParentFileName']}
                ))
    return relations


def get_sightings_from_ah(client, event, observable, count):
    sighting = {
        'type': 'sighting',
        'confidence': 'High',
        'internal': True,
        'source': 'Microsoft Defender ATP',
        'sensor': 'endpoint',
        **CTIM_SCHEMA_VERSION
    }

    relations = []
    targets = []
    if observable['type'] == 'domain':
        relations = _get_domain(event, client)
    elif observable['type'] == 'ip':
        relations = _get_ip(event, client)
    elif observable['type'] in ('sha1', 'sha256', 'md5'):
        relations = _get_file(event, client)

    targets.append(_get_target_from_ah(client, event))

    sighting['relations'] = relations

    sighting['targets'] = targets

    sighting['id'] = f'transient-sighting:{uuid.uuid4()}'
    sighting['count'] = count

    sighting['observables'] = [observable, ]

    sighting['observed_time'] = {'start_time': event['Timestamp']}
    return sighting
