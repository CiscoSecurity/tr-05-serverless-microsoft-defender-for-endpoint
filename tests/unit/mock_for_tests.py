RAW_RESPONSE_MOCK = {"value": [{
    "id": "da637232753436918895_1129806926",
    "incidentId": 9,
    "investigationId": 7,
    "assignedTo": None,
    "severity": "Medium",
    "status": "New",
    "classification": None,
    "determination": None,
    "investigationState": "PendingApproval",
    "detectionSource": "WindowsDefenderAtp",
    "category": "DefenseEvasion",
    "threatFamilyName": None,
    "title": "Suspicious process injection observed",
    "description": "A description.",
    "alertCreationTime": "2020-04-23T21:49:03.4731342Z",
    "firstEventTime": "2020-04-23T21:45:29.7876586Z",
    "lastEventTime": "2020-04-23T21:45:29.7876586Z",
    "lastUpdateTime": "2020-04-23T22:49:12.4166667Z",
    "resolvedTime": None,
    "machineId": "ebfef0ac4aa2ab0b4342c9cd078a6dfb6c66adc0",
    "computerDnsName": "desktop-au3ip5k",
    "aadTenantId": "50920398-8d61-4533-a89f-da28c22f8add",
    "relatedUser": {"userName": "Serhii", "domainName": "DESKTOP-AU3IP5K"},
    "comments": [],
    "evidence": [
        {"entityType": "Process",
         "sha1": "36c5d12033b2eaf251bae61c00690ffb17fddc87",
         "sha256": "908b64b1971a979c7e3e8ce4621945cb"
                   "a84854cb98d76367b791a6e22b5f6d53",
         "fileName": "powershell.exe",
         "filePath": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0",
         "processId": 7248,
         "processCommandLine": "powershell.exe",
         "processCreationTime": "2020-04-23T21:45:05.2801569Z",
         "parentProcessId": 7700,
         "parentProcessCreationTime": "2020-04-23T21:35:19.6505701Z",
         "ipAddress": None,
         "url": None,
         "accountName": None,
         "domainName": None,
         "userSid": None,
         "aadUserId": None,
         "userPrincipalName": None},
        {"entityType": "Process",
         "sha1": "c401cd335ba6a3bdaf8799fdc09cdc0721f06015",
         "sha256": "e5d90beeb6f13f4613c3153dabbd1466"
                   "f4a062b7252d931f37210907a7f914f7",
         "fileName": "notepad.exe",
         "filePath": "C:\\Windows\\System32",
         "processId": 8596,
         "processCommandLine": "notepad.exe",
         "processCreationTime": "2020-04-23T21:45:29.2017339Z",
         "parentProcessId": 7248,
         "parentProcessCreationTime": "2020-04-23T21:45:05.2801569Z",
         "ipAddress": None,
         "url": None,
         "accountName": None,
         "domainName": None,
         "userSid": None,
         "aadUserId": None,
         "userPrincipalName": None},
        {"entityType": "User",
         "sha1": None,
         "sha256": None,
         "fileName": None,
         "filePath": None,
         "processId": None,
         "processCommandLine": None,
         "processCreationTime": None,
         "parentProcessId": None,
         "parentProcessCreationTime": None,
         "ipAddress": None,
         "url": None,
         "accountName": "Serhii",
         "domainName": "DESKTOP-AU3IP5K",
         "userSid": "S-1-5-21-2782702779-1769723919-1938768942-1001",
         "aadUserId": None,
         "userPrincipalName": None}
    ]
}, ]}

EXPECTED_RESPONSE = {
    'data': {'sightings': {'count': 2, 'docs': [{
        'type': 'sighting',
        'confidence': 'High',
        'internal': True,
        'source': 'Microsoft Defender ATP',
        'sensor': 'endpoint',
        'schema_version': '1.0.16',
        'targets': [],
        'relations': [{
            'origin': 'WindowsDefenderAv',
            'relation': 'File_Name_Of',
            'source': {
                'value': 'Ransomware.WannaCry.zip', 'type': 'file_name'},
            'related': {
                'value': 'ba5de52939cb809eae10fdbb7fac47095a9599a7',
                'type': 'sha1'
            }},
            {'origin': 'WindowsDefenderAv',
             'relation': 'File_Name_Of',
             'source': {
                 'value': 'Ransomware.WannaCry.zip',
                 'type': 'file_name'
             },
             'related': {
                 'value': '707a9f323556179571bc832e34fa5920'
                          '66b1d5f2cac4a7426fe163597e3e618a',
                 'type': 'sha256'
             }},
            {'origin': 'WindowsDefenderAv',
             'relation': 'File_Path_Of',
             'source': {
                 'value': 'C:\\Users\\Serhii\\Downloads',
                 'type': 'file_path'
             },
             'related': {
                 'value': 'ba5de52939cb809eae10fdbb7fac47095a9599a7',
                 'type': 'sha1'
             }},
            {'origin': 'WindowsDefenderAv',
             'relation': 'File_Path_Of',
             'source': {'value': 'C:\\Users\\Serhii\\Downloads',
                        'type': 'file_path'}, 'related': {
                'value': '707a9f323556179571bc832e34fa5920'
                         '66b1d5f2cac4a7426fe163597e3e618a',
                'type': 'sha256'}},
            {'origin': 'WindowsDefenderAv',
             'relation': 'File_Name_Of',
             'source': {'value': 'Dino.zip', 'type': 'file_name'},
             'related': {
                 'value': 'e6c442016aa3c25c54e32cf9637a0b79ebaaa5e1',
                 'type': 'sha1'}},
            {'origin': 'WindowsDefenderAv',
             'relation': 'File_Name_Of',
             'source': {'value': 'Dino.zip', 'type': 'file_name'},
             'related': {
                 'value': '66fb3bfdb601414cd35623d3dab81121'
                          '5f8dfa08c4189df588872fb543568684',
                 'type': 'sha256'}},
            {'origin': 'WindowsDefenderAv',
             'relation': 'File_Path_Of',
             'source': {'value': 'C:\\Users\\Serhii\\Downloads',
                        'type': 'file_path'}, 'related': {
                'value': 'e6c442016aa3c25c54e32cf9637a0b79ebaaa5e1',
                'type': 'sha1'}},
            {'origin': 'WindowsDefenderAv',
             'relation': 'File_Path_Of',
             'source': {'value': 'C:\\Users\\Serhii\\Downloads',
                        'type': 'file_path'}, 'related': {
                'value': '66fb3bfdb601414cd35623d3dab81121'
                         '5f8dfa08c4189df588872fb543568684',
                'type': 'sha256'}},
            {'origin': 'WindowsDefenderAv',
             'relation': 'File_Name_Of',
             'source': {'value': 'AntiExe.A.zip',
                        'type': 'file_name'},
             'related': {
                 'value': '8fa3b60ea7b526b46ca22fa6544443a670a7de46',
                 'type': 'sha1'}},
            {'origin': 'WindowsDefenderAv',
             'relation': 'File_Name_Of',
             'source': {'value': 'AntiExe.A.zip',
                        'type': 'file_name'},
             'related': {
                 'value': '93861a8aa9a4f42489d029c64bc0599c'
                          '208971891c70a9b2192b60e20c57d3bc',
                 'type': 'sha256'}},
            {'origin': 'WindowsDefenderAv',
             'relation': 'File_Path_Of',
             'source': {'value': 'C:\\Users\\Serhii\\Downloads',
                        'type': 'file_path'}, 'related': {
                'value': '8fa3b60ea7b526b46ca22fa6544443a670a7de46',
                'type': 'sha1'}},
            {'origin': 'WindowsDefenderAv',
             'relation': 'File_Path_Of',
             'source': {'value': 'C:\\Users\\Serhii\\Downloads',
                        'type': 'file_path'}, 'related': {
                'value': '93861a8aa9a4f42489d029c64bc0599c'
                         '208971891c70a9b2192b60e20c57d3bc',
                'type': 'sha256'}},
            {'origin': 'WindowsDefenderAv',
             'relation': 'File_Name_Of',
             'source': {'value': 'Ransomware.WannaCry[1].zip',
                        'type': 'file_name'}, 'related': {
                'value': 'ba5de52939cb809eae10fdbb7fac47095a9599a7',
                'type': 'sha1'}},
            {'origin': 'WindowsDefenderAv',
             'relation': 'File_Path_Of',
             'source': {
                 'value': 'C:\\Users\\Serhii\\AppData\\Local\\Packages\\'
                          'Microsoft.MicrosoftEdge_8wekyb3d8bbwe\\AC\\'
                          '#!001\\MicrosoftEdge\\Cache\\5WDW06DN',
                 'type': 'file_path'}, 'related': {
                'value': 'ba5de52939cb809eae10fdbb7fac47095a9599a7',
                'type': 'sha1'}},
            {'origin': 'WindowsDefenderAv',
             'relation': 'File_Name_Of',
             'source': {'value': 'AntiExe.A[1].zip',
                        'type': 'file_name'},
             'related': {
                 'value': '8fa3b60ea7b526b46ca22fa6544443a670a7de46',
                 'type': 'sha1'}},
            {'origin': 'WindowsDefenderAv',
             'relation': 'File_Path_Of',
             'source': {
                 'value': 'C:\\Users\\Serhii\\AppData\\Local\\Packages\\'
                          'Microsoft.MicrosoftEdge_8wekyb3d8bbwe\\AC\\'
                          '#!001\\MicrosoftEdge\\Cache\\ITPWIEMR',
                 'type': 'file_path'}, 'related': {
                'value': '8fa3b60ea7b526b46ca22fa6544443a670a7de46',
                'type': 'sha1'}},
            {'origin': 'WindowsDefenderAv',
             'relation': 'File_Name_Of',
             'source': {'value': 'Dino[1].zip', 'type': 'file_name'},
             'related': {
                 'value': 'e6c442016aa3c25c54e32cf9637a0b79ebaaa5e1',
                 'type': 'sha1'}},
            {'origin': 'WindowsDefenderAv',
             'relation': 'File_Path_Of',
             'source': {
                 'value': 'C:\\Users\\Serhii\\AppData\\Local\\Packages\\'
                          'Microsoft.MicrosoftEdge_8wekyb3d8bbwe\\AC\\'
                          '#!001\\MicrosoftEdge\\Cache\\ITPWIEMR',
                 'type': 'file_path'}, 'related': {
                'value': 'e6c442016aa3c25c54e32cf9637a0b79ebaaa5e1',
                'type': 'sha1'}},
            {'origin': 'WindowsDefenderAv',
             'relation': 'File_Name_Of',
             'source': {'value': 'APT34.zip', 'type': 'file_name'},
             'related': {
                 'value': '3c61a2ac4276155094ff7f77d1d6400197ff2d93',
                 'type': 'sha1'}},
            {'origin': 'WindowsDefenderAv',
             'relation': 'File_Name_Of',
             'source': {'value': 'APT34.zip', 'type': 'file_name'},
             'related': {
                 'value': '4698791decea6748d82a591eb519cff3'
                          'ff178e5f168c2a9f4fe70468e267b369',
                 'type': 'sha256'}},
            {'origin': 'WindowsDefenderAv',
             'relation': 'File_Path_Of',
             'source': {'value': 'C:\\Users\\Serhii\\Downloads',
                        'type': 'file_path'}, 'related': {
                'value': '3c61a2ac4276155094ff7f77d1d6400197ff2d93',
                'type': 'sha1'}},
            {'origin': 'WindowsDefenderAv',
             'relation': 'File_Path_Of',
             'source': {'value': 'C:\\Users\\Serhii\\Downloads',
                        'type': 'file_path'}, 'related': {
                'value': '4698791decea6748d82a591eb519cff3'
                         'ff178e5f168c2a9f4fe70468e267b369',
                'type': 'sha256'}},
            {'origin': 'WindowsDefenderAv',
             'relation': 'File_Name_Of',
             'source': {'value': 'APT34[1].zip', 'type': 'file_name'},
             'related': {
                 'value': '3c61a2ac4276155094ff7f77d1d6400197ff2d93',
                 'type': 'sha1'}},
            {'origin': 'WindowsDefenderAv',
             'relation': 'File_Path_Of',
             'source': {
                 'value': 'C:\\Users\\Serhii\\AppData\\Local\\Packages\\'
                          'Microsoft.MicrosoftEdge_8wekyb3d8bbwe\\AC\\'
                          '#!001\\MicrosoftEdge\\Cache\\ITPWIEMR',
                 'type': 'file_path'}, 'related': {
                'value': '3c61a2ac4276155094ff7f77d1d6400197ff2d93',
                'type': 'sha1'}},
            {'origin': 'WindowsDefenderAv',
             'relation': 'File_Name_Of',
             'source': {'value': 'Ransomware.Rex.zip',
                        'type': 'file_name'}, 'related': {
                'value': '0d549631690ea297c25b2a4e133cacb8a87b97c6',
                'type': 'sha1'}},
            {'origin': 'WindowsDefenderAv',
             'relation': 'File_Name_Of',
             'source': {'value': 'Ransomware.Rex.zip',
                        'type': 'file_name'}, 'related': {
                'value': '32856e998ff1a8b89e30c9658721595d'
                         '403ff0eece70dc803a36d1939e429f8d',
                'type': 'sha256'}},
            {'origin': 'WindowsDefenderAv',
             'relation': 'File_Path_Of',
             'source': {'value': 'C:\\Users\\Serhii\\Downloads',
                        'type': 'file_path'}, 'related': {
                'value': '0d549631690ea297c25b2a4e133cacb8a87b97c6',
                'type': 'sha1'}},
            {'origin': 'WindowsDefenderAv',
             'relation': 'File_Path_Of',
             'source': {'value': 'C:\\Users\\Serhii\\Downloads',
                        'type': 'file_path'}, 'related': {
                'value': '32856e998ff1a8b89e30c9658721595d'
                         '403ff0eece70dc803a36d1939e429f8d',
                'type': 'sha256'}},
            {'origin': 'WindowsDefenderAv',
             'relation': 'File_Name_Of',
             'source': {'value': 'VBS.Hopper.zip',
                        'type': 'file_name'},
             'related': {
                 'value': '0b109ff594e05cc8ac137d51bcd540ebe27afc0c',
                 'type': 'sha1'}},
            {'origin': 'WindowsDefenderAv',
             'relation': 'File_Name_Of',
             'source': {'value': 'VBS.Hopper.zip',
                        'type': 'file_name'},
             'related': {
                 'value': '805585d028fa2466846ab544431f0d4c'
                          '6c7de4d8ef31620af65b537fbd66990b',
                 'type': 'sha256'}},
            {'origin': 'WindowsDefenderAv',
             'relation': 'File_Path_Of',
             'source': {'value': 'C:\\Users\\Serhii\\Downloads',
                        'type': 'file_path'}, 'related': {
                'value': '0b109ff594e05cc8ac137d51bcd540ebe27afc0c',
                'type': 'sha1'}},
            {'origin': 'WindowsDefenderAv',
             'relation': 'File_Path_Of',
             'source': {'value': 'C:\\Users\\Serhii\\Downloads',
                        'type': 'file_path'}, 'related': {
                'value': '805585d028fa2466846ab544431f0d4c'
                         '6c7de4d8ef31620af65b537fbd66990b',
                'type': 'sha256'}},
            {'origin': 'WindowsDefenderAv',
             'relation': 'File_Name_Of',
             'source': {'value': 'VBS.Hopper[1].zip',
                        'type': 'file_name'}, 'related': {
                'value': '0b109ff594e05cc8ac137d51bcd540ebe27afc0c',
                'type': 'sha1'}},
            {'origin': 'WindowsDefenderAv',
             'relation': 'File_Path_Of',
             'source': {
                 'value': 'C:\\Users\\Serhii\\AppData\\Local\\Packages\\'
                          'Microsoft.MicrosoftEdge_8wekyb3d8bbwe\\AC\\'
                          '#!001\\MicrosoftEdge\\Cache\\ITPWIEMR',
                 'type': 'file_path'}, 'related': {
                'value': '0b109ff594e05cc8ac137d51bcd540ebe27afc0c',
                'type': 'sha1'}},
            {'origin': 'WindowsDefenderAv',
             'relation': 'File_Name_Of',
             'source': {'value': 'Ransomware.Rex[1].zip',
                        'type': 'file_name'}, 'related': {
                'value': '0d549631690ea297c25b2a4e133cacb8a87b97c6',
                'type': 'sha1'}},
            {'origin': 'WindowsDefenderAv',
             'relation': 'File_Path_Of',
             'source': {
                 'value': 'C:\\Users\\Serhii\\AppData\\Local\\Packages\\'
                          'Microsoft.MicrosoftEdge_8wekyb3d8bbwe\\AC\\'
                          '#!001\\MicrosoftEdge\\Cache\\HCRKS966',
                 'type': 'file_path'}, 'related': {
                'value': '0d549631690ea297c25b2a4e133cacb8a87b97c6',
                'type': 'sha1'}}],
        'id': 'transient-sighting:0866fbfe-a311-40c2-b51d-5fa5d898d935',
        'count': 2,
        'observables': [
            {'type': 'sha1',
             'value': '0d549631690ea297c25b2a4e133cacb8a87b97c6'}],
        'observed_time': {
            'start_time': '2020-05-28T06:52:39.8400379Z',
            'end_time': '2020-05-28T06:52:39.8400379Z'
        },
        'title': "'Vigorf' malware was detected",
        'description': 'Malware and unwanted software are undesirable '
                       'applications that perform annoying, disruptive, '
                       'or harmful actions on affected machines. '
                       'Some of these undesirable applications can '
                       'replicate and spread from one machine to another. '
                       'Others are able to receive commands from remote '
                       'attackers and perform activities associated with '
                       'cyber attacks.\n\nThis detection might indicate '
                       'that the malware was stopped from delivering its '
                       'payload. However, it is prudent to check the '
                       'machine for signs of infection.',
        'severity': 'Info', 'timestamp': '2020-05-31T10:44:12.9Z',
        'source_uri': 'https://securitycenter.windows.com/files/'
                      '0d549631690ea297c25b2a4e133cacb8a87b97c6/alerts'},
        {'type': 'sighting', 'confidence': 'High', 'internal': True,
         'source': 'Microsoft Defender ATP', 'sensor': 'endpoint',
         'schema_version': '1.0.16', 'relations': [
            {'origin': 'Microsoft Defender ATP',
             'relation': 'File_Name_Of',
             'source': {'type': 'file_name',
                        'value': 'Ransomware.Rex[1].zip'},
             'related': {'type': 'sha1',
                         'value': '0d549631690ea297c25b2a4e133cacb8a87b97c6'}},
            {'origin': 'Microsoft Defender ATP',
             'relation': 'File_Name_Of',
             'source': {'type': 'file_name',
                        'value': 'Ransomware.Rex[1].zip'},
             'related': {'type': 'sha256',
                         'value': '32856e998ff1a8b89e30c9658721595d'
                                  '403ff0eece70dc803a36d1939e429f8d'}},
            {'origin': 'Microsoft Defender ATP',
             'relation': 'File_Name_Of',
             'source': {'type': 'file_name',
                        'value': 'Ransomware.Rex[1].zip'},
             'related': {'type': 'md5',
                         'value': '50188823168525455c273c07d8457b87'}},
            {'origin': 'Microsoft Defender ATP',
             'relation': 'File_Path_Of',
             'source': {'type': 'file_path',
                        'value': 'C:\\Users\\Serhii\\'
                                 'AppData\\Local\\Packages\\'
                                 'Microsoft.MicrosoftEdge_8wekyb3d8bbwe\\AC\\'
                                 '#!001\\MicrosoftEdge\\Cache\\HCRKS966\\'
                                 'Ransomware.Rex[1].zip'},
             'related': {'type': 'file_name',
                         'value': 'Ransomware.Rex[1].zip'}},
            {'origin': 'Microsoft Defender ATP',
             'relation': 'Related_To',
             'source': {'type': 'file_name',
                        'value': 'MicrosoftEdgeCP.exe'},
             'related': {'type': 'file_name',
                         'value': 'Ransomware.Rex[1].zip'}},
            {'origin': 'Microsoft Defender ATP',
             'relation': 'File_Name_Of',
             'source': {'type': 'file_name',
                        'value': 'MicrosoftEdgeCP.exe'},
             'related': {'type': 'sha1',
                         'value': 'ecb05717e416d965255387f4edc196889aa12c67'}},
            {'origin': 'Microsoft Defender ATP',
             'relation': 'File_Name_Of',
             'source': {'type': 'file_name',
                        'value': 'MicrosoftEdgeCP.exe'},
             'related': {'type': 'sha256',
                         'value': 'ee7174ee353e7d29ce17d29d66411b36'
                                  '23c39d9dec3f439e35af47a7e7a7c895'}},
            {'origin': 'Microsoft Defender ATP',
             'relation': 'File_Name_Of',
             'source': {'type': 'file_name',
                        'value': 'MicrosoftEdgeCP.exe'},
             'related': {'type': 'md5',
                         'value': '0e954887fc791f668ce388f89bc3d6c6'}},
            {'origin': 'Microsoft Defender ATP',
             'relation': 'File_Path_Of',
             'source': {'type': 'file_path',
                        'value': 'c:\\windows\\system32\\microsoftedgecp.exe'},
             'related': {'type': 'file_name',
                         'value': 'MicrosoftEdgeCP.exe'}},
            {'origin': 'Microsoft Defender ATP',
             'relation': 'Related_To',
             'source': {'type': 'file_name',
                        'value': 'MicrosoftEdgeCP.exe'},
             'related': {'type': 'file_name',
                         'value': 'svchost.exe'}}],
         'targets': [{'type': 'endpoint', 'os': 'Windows10',
                      'observables': [
                          {'type': 'hostname',
                           'value': 'DESKTOP-AU3IP5K'},
                          {'type': 'ip', 'value': '10.0.2.15'}],
                      'observed_time': {
                          'start_time': '2020-05-28T07:06:58.4340352Z',
                          'end_time': '2020-05-28T07:06:58.4340352Z'
                      }}],
         'id': 'transient-sighting:ded6f089-ea5e-401d-a0ba-aed6457d4ba1',
         'count': 2,
         'observables': [
             {'type': 'sha1',
              'value': '0d549631690ea297c25b2a4e133cacb8a87b97c6'}],
         'observed_time': {
             'start_time': '2020-05-28T07:06:58.4340352Z',
             'end_time': '2020-05-28T07:06:58.4340352Z'
         }}]}
             }
}


EXPECTED_RESPONSE_AUTH_ERROR = {
    "errors": [
        {
            "code": "permission denied",
            "message": "Invalid Authorization Bearer JWT.",
            "type": "fatal"
        }
    ]
}


EXPECTED_RESPONSE_INVALID_CREDENTIALS_ERROR = {
    "errors": [
        {
            "code": "permission denied",
            "message": "The request is missing valid credentials.",
            "type": "fatal"
        }
    ]
}


EXPECTED_RESPONSE_500_ERROR = {
    "errors": [
        {
            "code": "internal error",
            "message": "Microsoft Defender ATP internal error.",
            "type": "fatal"
        }
    ]
}


EXPECTED_RESPONSE_429_ERROR = {
    "errors": [
        {
            "code": "too many requests",
            "message": "Too many requests to Microsoft Defender ATP "
                       "have been made. Please, try again later.",
            "type": "fatal"
        }
    ]
}


EXPECTED_RESPONSE_400_ERROR = {
    "errors": [
        {
            "code": "invalid request",
            "message": "Invalid request to Microsoft Defender ATP. "
                       "Access Token does not exist.",
            "type": "fatal"
        }
    ]
}


GET_SHA256_FOR_0d549631690ea297c25b2a4e133cacb8a87b97c6 = {
    '@odata.context': 'https://api.securitycenter.windows.com/'
                      'api/v1.0/$metadata#Files/$entity',
    'sha1': '0d549631690ea297c25b2a4e133cacb8a87b97c6',
    'sha256': '32856e998ff1a8b89e30c9658721595d'
              '403ff0eece70dc803a36d1939e429f8d',
    'md5': '50188823168525455c273c07d8457b87',
    'globalPrevalence': 15,
    'globalFirstObserved': '2017-03-16T12:02:32.4527362Z',
    'globalLastObserved': '2020-06-17T06:54:07.852862Z',
    'size': 2843585,
    'fileType': None,
    'isPeFile': False,
    'filePublisher': None,
    'fileProductName': None,
    'signer': None,
    'issuer': None,
    'signerHash': None,
    'isValidCertificate': None,
    'determinationType': 'Unknown',
    'determinationValue': ''}


GET_SHA256_FOR_ecb05717e416d965255387f4edc196889aa12c67 = {
    '@odata.context': 'https://api.securitycenter.windows.com/'
                      'api/v1.0/$metadata#Files/$entity',
    'sha1': 'ecb05717e416d965255387f4edc196889aa12c67',
    'sha256': 'ee7174ee353e7d29ce17d29d66411b36'
              '23c39d9dec3f439e35af47a7e7a7c895',
    'md5': '0e954887fc791f668ce388f89bc3d6c6',
    'globalPrevalence': 960835,
    'globalFirstObserved': '2019-03-20T20:18:55.4327667Z',
    'globalLastObserved': '2020-06-18T11:01:12.3779721Z',
    'size': 94720,
    'fileType': None,
    'isPeFile': True,
    'filePublisher': None,
    'fileProductName': None,
    'signer': 'Microsoft Windows',
    'issuer': 'Microsoft Windows Production PCA 2011',
    'signerHash': '84ec67b9ac9d7789bab500503a7862173f432adb',
    'isValidCertificate': True,
    'determinationType': 'Unknown',
    'determinationValue': ''}


AH_RESPONSE = {
    "Stats": {
        "ExecutionTime": 0.0312486,
        "resource_usage": {
            "cache": {
                "memory": {
                    "hits": 110,
                    "misses": 0,
                    "total": 110
                },
                "disk": {
                    "hits": 0,
                    "misses": 0,
                    "total": 0
                }
            },
            "cpu": {
                "user": "00:00:00",
                "kernel": "00:00:00.0312500",
                "total cpu": "00:00:00.0312500"
            },
            "memory": {
                "peak_per_node": 167773216
            }
        },
        "dataset_statistics": [
            {
                "table_row_count": 3,
                "table_size": 2639
            }
        ]
    },
    "Schema": [
        {
            "Name": "Timestamp",
            "Type": "DateTime"
        },
        {
            "Name": "DeviceId",
            "Type": "String"
        },
        {
            "Name": "DeviceName",
            "Type": "String"
        },
        {
            "Name": "ActionType",
            "Type": "String"
        },
        {
            "Name": "FileName",
            "Type": "String"
        },
        {
            "Name": "FolderPath",
            "Type": "String"
        },
        {
            "Name": "SHA1",
            "Type": "String"
        },
        {
            "Name": "SHA256",
            "Type": "String"
        },
        {
            "Name": "MD5",
            "Type": "String"
        },
        {
            "Name": "FileOriginUrl",
            "Type": "String"
        },
        {
            "Name": "FileOriginReferrerUrl",
            "Type": "String"
        },
        {
            "Name": "FileOriginIP",
            "Type": "String"
        },
        {
            "Name": "FileSize",
            "Type": "Int64"
        },
        {
            "Name": "InitiatingProcessAccountDomain",
            "Type": "String"
        },
        {
            "Name": "InitiatingProcessAccountName",
            "Type": "String"
        },
        {
            "Name": "InitiatingProcessAccountSid",
            "Type": "String"
        },
        {
            "Name": "InitiatingProcessAccountUpn",
            "Type": "String"
        },
        {
            "Name": "InitiatingProcessAccountObjectId",
            "Type": "String"
        },
        {
            "Name": "InitiatingProcessMD5",
            "Type": "String"
        },
        {
            "Name": "InitiatingProcessSHA1",
            "Type": "String"
        },
        {
            "Name": "InitiatingProcessSHA256",
            "Type": "String"
        },
        {
            "Name": "InitiatingProcessFolderPath",
            "Type": "String"
        },
        {
            "Name": "InitiatingProcessFileName",
            "Type": "String"
        },
        {
            "Name": "InitiatingProcessId",
            "Type": "Int64"
        },
        {
            "Name": "InitiatingProcessCommandLine",
            "Type": "String"
        },
        {
            "Name": "InitiatingProcessCreationTime",
            "Type": "DateTime"
        },
        {
            "Name": "InitiatingProcessIntegrityLevel",
            "Type": "String"
        },
        {
            "Name": "InitiatingProcessTokenElevation",
            "Type": "String"
        },
        {
            "Name": "InitiatingProcessParentId",
            "Type": "Int64"
        },
        {
            "Name": "InitiatingProcessParentFileName",
            "Type": "String"
        },
        {
            "Name": "InitiatingProcessParentCreationTime",
            "Type": "DateTime"
        },
        {
            "Name": "RequestProtocol",
            "Type": "String"
        },
        {
            "Name": "ShareName",
            "Type": "String"
        },
        {
            "Name": "RequestSourceIP",
            "Type": "String"
        },
        {
            "Name": "RequestSourcePort",
            "Type": "Int32"
        },
        {
            "Name": "RequestAccountName",
            "Type": "String"
        },
        {
            "Name": "RequestAccountDomain",
            "Type": "String"
        },
        {
            "Name": "RequestAccountSid",
            "Type": "String"
        },
        {
            "Name": "SensitivityLabel",
            "Type": "String"
        },
        {
            "Name": "SensitivitySubLabel",
            "Type": "String"
        },
        {
            "Name": "IsAzureInfoProtectionApplied",
            "Type": "SByte"
        },
        {
            "Name": "ReportId",
            "Type": "Int64"
        },
        {
            "Name": "AppGuardContainerId",
            "Type": "String"
        }
    ],
    "Results": [
        {
            "Timestamp": "2020-05-28T07:06:58.4340352Z",
            "DeviceId": "ebfef0ac4aa2ab0b4342c9cd078a6dfb6c66adc0",
            "DeviceName": "desktop-au3ip5k",
            "ActionType": "FileCreated",
            "FileName": "Ransomware.Rex[1].zip",
            "FolderPath": "C:\\Users\\Serhii\\AppData\\Local\\Packages\\"
                          "Microsoft.MicrosoftEdge_8wekyb3d8bbwe\\AC\\"
                          "#!001\\MicrosoftEdge\\Cache\\HCRKS966\\"
                          "Ransomware.Rex[1].zip",
            "SHA1": "0d549631690ea297c25b2a4e133cacb8a87b97c6",
            "SHA256": "",
            "MD5": "50188823168525455c273c07d8457b87",
            "FileOriginUrl": "",
            "FileOriginReferrerUrl": "",
            "FileOriginIP": "",
            "FileSize": 2843585,
            "InitiatingProcessAccountDomain": "desktop-au3ip5k",
            "InitiatingProcessAccountName": "serhii",
            "InitiatingProcessAccountSid": "S-1-5-21-2782702779-1769723919-"
                                           "1938768942-1001",
            "InitiatingProcessAccountUpn": "",
            "InitiatingProcessAccountObjectId": "",
            "InitiatingProcessMD5": "0e954887fc791f668ce388f89bc3d6c6",
            "InitiatingProcessSHA1": "ecb05717e416d9652553"
                                     "87f4edc196889aa12c67",
            "InitiatingProcessSHA256": "",
            "InitiatingProcessFolderPath": "c:\\windows\\system32\\"
                                           "microsoftedgecp.exe",
            "InitiatingProcessFileName": "MicrosoftEdgeCP.exe",
            "InitiatingProcessId": 5788,
            "InitiatingProcessCommandLine": "\"MicrosoftEdgeCP.exe\" "
                                            "-ServerName:Windows.Internal."
                                            "WebRuntime.ContentProcessServer",
            "InitiatingProcessCreationTime": "2020-05-28T06:49:10.9330787Z",
            "InitiatingProcessIntegrityLevel": "Low",
            "InitiatingProcessTokenElevation": "TokenElevationTypeLimited",
            "InitiatingProcessParentId": 804,
            "InitiatingProcessParentFileName": "svchost.exe",
            "InitiatingProcessParentCreationTime": "2020-05-25T"
                                                   "17:12:09.5929805Z",
            "RequestProtocol": "Local",
            "ShareName": "",
            "RequestSourceIP": "",
            "RequestSourcePort": None,
            "RequestAccountName": "Serhii",
            "RequestAccountDomain": "DESKTOP-AU3IP5K",
            "RequestAccountSid": "S-1-5-21-2782702779-1769723919-"
                                 "1938768942-1001",
            "SensitivityLabel": "",
            "SensitivitySubLabel": "",
            "IsAzureInfoProtectionApplied": None,
            "ReportId": 14689,
            "AppGuardContainerId": ""
        },
    ]
}

EXPECTED_RESPONSE_RESPOND_OBSERVABLE = {
  "data": [
    {
      "categories": [
        "Microsoft Defender ATP",
        "Submit Indicator"
      ],
      "description": "Submit indicator with alert action for DOMAIN",
      "id": "microsoft-defender-atp-submit-indicator-alert",
      "query-params": {
        "observable_type": "domain",
        "observable_value": "asdf.com"
      },
      "title": "Submit indicator with Alert"
    },
    {
      "categories": [
        "Microsoft Defender ATP",
        "Submit Indicator"
      ],
      "description": "Submit indicator with Alert and Block action for DOMAIN",
      "id": "microsoft-defender-atp-submit-indicator-alert-and-block",
      "query-params": {
        "observable_type": "domain",
        "observable_value": "asdf.com"
      },
      "title": "Submit indicator with Alert and Block"
    },
    {
      "categories": [
        "Microsoft Defender ATP",
        "Submit Indicator"
      ],
      "description": "Submit indicator with Allowed action for DOMAIN",
      "id": "microsoft-defender-atp-submit-indicator-allowed",
      "query-params": {
        "observable_type": "domain",
        "observable_value": "asdf.com"
      },
      "title": "Submit indicator with Allowed"
    }
  ]
}

RAW_RESPONSE_TRIGGER_OBSERVABLE = {
    '@odata.context': 'https://api.securitycenter.windows.com/api/v1.0'
                      '/$metadata#Indicators/$entity',
    'id': '13',
    'indicatorValue': 'asdf.com',
    'indicatorType': 'DomainName',
    'action': 'Alert',
    'createdBy': '0006810a-4b24-40b7-862b-6e30a2ed88d4',
    'source': 'Defender ATP Relay API',
    'sourceType': 'AadApp',
    'severity': 'High',
    'category': 1,
    'application': None,
    'educateUrl': None,
    'bypassDurationHours': None,
    'title': 'From SecureX Threat Response',
    'description': 'This indicator was added via SecureX Threat Response '
                   'by the UI or API response actions',
    'recommendedActions': None,
    'creationTimeDateTimeUtc': '2020-07-13T16:49:50.290203Z',
    'expirationTime': None,
    'lastUpdateTime': '2020-07-13T16:49:50.290203Z',
    'lastUpdatedBy': None, 'rbacGroupNames': [],
    'rbacGroupIds': [],
    'notificationId': None,
    'notificationBody': None,
    'version': None,
    'mitreTechniques': [],
    'historicalDetection': False,
    'lookBackPeriod': None,
    'generateAlert': True,
    'additionalInfo': None,
    'createdByDisplayName': 'Defender ATP Relay API',
    'createdBySource': 'PublicApi',
    'certificateInfo': None
}
