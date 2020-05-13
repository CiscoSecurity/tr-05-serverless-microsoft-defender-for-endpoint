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
         "accountName": "TestUser",
         "domainName": "DESKTOP-AU3IP5K",
         "userSid": "S-1-5-21-2782702779-1769723919-1938768942-1001",
         "aadUserId": None,
         "userPrincipalName": None}
    ]
}, ]}


EXPECTED_RESPONSE = {
  "data": {
    "sightings": {
      "count": 1,
      "docs": [
        {
          "confidence": "High",
          "count": 1,
          "description": "A description.",
          "id": "transient:8c7e1132-3d36-4e23-af9f-391a4c275c9d",
          "internal": True,
          "observables": [
            {
              "type": "sha256",
              "value": "36c5d12033b2eaf251bae61c00690ffb17fddc87"
            }
          ],
          "observed_time": {
            "start_time": "2020-04-23T15:59:57.6407597Z"
          },
          "relations": [
            {
              "origin": "WindowsDefenderAtp",
              "related": {
                "type": "sha1",
                "value": "36c5d12033b2eaf251bae61c00690ffb17fddc87"
              },
              "relation": "File_Name_Of",
              "source": {
                "type": "file_name",
                "value": "powershell.exe"
              }
            },
            {
              "origin": "WindowsDefenderAtp",
              "related": {
                "type": "sha256",
                "value": "908b64b1971a979c7e3e8ce4621945cb"
                         "a84854cb98d76367b791a6e22b5f6d53"
              },
              "relation": "File_Name_Of",
              "source": {
                "type": "file_name",
                "value": "powershell.exe"
              }
            },
            {
              "origin": "WindowsDefenderAtp",
              "related": {
                "type": "sha1",
                "value": "36c5d12033b2eaf251bae61c00690ffb17fddc87"
              },
              "relation": "File_Path_Of",
              "source": {
                "type": "file_path",
                "value": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0"
              }
            },
            {
              "origin": "WindowsDefenderAtp",
              "related": {
                "type": "sha256",
                "value": "908b64b1971a979c7e3e8ce4621945cb"
                         "a84854cb98d76367b791a6e22b5f6d53"
              },
              "relation": "File_Path_Of",
              "source": {
                "type": "file_path",
                "value": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0"
              }
            },
            {
              "origin": "WindowsDefenderAtp",
              "related": {
                "type": "sha1",
                "value": "c401cd335ba6a3bdaf8799fdc09cdc0721f06015"
              },
              "relation": "File_Name_Of",
              "source": {
                "type": "file_name",
                "value": "notepad.exe"
              }
            },
            {
              "origin": "WindowsDefenderAtp",
              "related": {
                "type": "sha256",
                "value": "e5d90beeb6f13f4613c3153dabbd1466"
                         "f4a062b7252d931f37210907a7f914f7"
              },
              "relation": "File_Name_Of",
              "source": {
                "type": "file_name",
                "value": "notepad.exe"
              }
            },
            {
              "origin": "WindowsDefenderAtp",
              "related": {
                "type": "sha1",
                "value": "c401cd335ba6a3bdaf8799fdc09cdc0721f06015"
              },
              "relation": "File_Path_Of",
              "source": {
                "type": "file_path",
                "value": "C:\\Windows\\System32"
              }
            },
            {
              "origin": "WindowsDefenderAtp",
              "related": {
                "type": "sha256",
                "value": "e5d90beeb6f13f4613c3153dabbd1466"
                         "f4a062b7252d931f37210907a7f914f7"
              },
              "relation": "File_Path_Of",
              "source": {
                "type": "file_path",
                "value": "C:\\Windows\\System32"
              }
            },
            {
              "origin": "WindowsDefenderAtp",
              "related": {
                "type": "sha1",
                "value": "36c5d12033b2eaf251bae61c00690ffb17fddc87"
              },
              "relation": "File_Name_Of",
              "source": {
                "type": "file_name",
                "value": "powershell.exe"
              }
            },
            {
              "origin": "WindowsDefenderAtp",
              "related": {
                "type": "sha256",
                "value": "908b64b1971a979c7e3e8ce4621945cb"
                         "a84854cb98d76367b791a6e22b5f6d53"
              },
              "relation": "File_Name_Of",
              "source": {
                "type": "file_name",
                "value": "powershell.exe"
              }
            },
            {
              "origin": "WindowsDefenderAtp",
              "related": {
                "type": "sha1",
                "value": "36c5d12033b2eaf251bae61c00690ffb17fddc87"
              },
              "relation": "File_Path_Of",
              "source": {
                "type": "file_path",
                "value": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0"
              }
            },
            {
              "origin": "WindowsDefenderAtp",
              "related": {
                "type": "sha256",
                "value": "908b64b1971a979c7e3e8ce4621945cb"
                         "a84854cb98d76367b791a6e22b5f6d53"
              },
              "relation": "File_Path_Of",
              "source": {
                "type": "file_path",
                "value": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0"
              }
            },
            {
              "origin": "WindowsDefenderAtp",
              "related": {
                "type": "sha1",
                "value": "c401cd335ba6a3bdaf8799fdc09cdc0721f06015"
              },
              "relation": "File_Name_Of",
              "source": {
                "type": "file_name",
                "value": "notepad.exe"
              }
            },
            {
              "origin": "WindowsDefenderAtp",
              "related": {
                "type": "sha256",
                "value": "e5d90beeb6f13f4613c3153dabbd1466"
                         "f4a062b7252d931f37210907a7f914f7"
              },
              "relation": "File_Name_Of",
              "source": {
                "type": "file_name",
                "value": "notepad.exe"
              }
            },
            {
              "origin": "WindowsDefenderAtp",
              "related": {
                "type": "sha1",
                "value": "c401cd335ba6a3bdaf8799fdc09cdc0721f06015"
              },
              "relation": "File_Path_Of",
              "source": {
                "type": "file_path",
                "value": "C:\\Windows\\System32"
              }
            },
            {
              "origin": "WindowsDefenderAtp",
              "related": {
                "type": "sha256",
                "value": "e5d90beeb6f13f4613c3153dabbd1466"
                         "f4a062b7252d931f37210907a7f914f7"
              },
              "relation": "File_Path_Of",
              "source": {
                "type": "file_path",
                "value": "C:\\Windows\\System32"
              }
            }
          ],
          "schema_version": "1.0.16",
          "sensor": "endpoint",
          "severity": "Medium",
          "source": "Microsoft Defender ATP",
          "source_uri": "https://securitycenter.windows.com/files"
                        "/36c5d12033b2eaf251bae61c00690ffb17fddc87/alerts",
          "targets": [
            {
              "observables": [
                {
                  "type": "hostname",
                  "value": "DESKTOP-AU3IP5K"
                }
              ],
              "observed_time": {
                "start_time": "2020-04-23T15:59:57.6407597Z"
              },
              "type": "endpoint"
            }
          ],
          "timestamp": "2020-04-23T21:49:04.5166667Z",
          "title": "Suspicious process injection observed",
          "type": "sighting"
        }
      ]
    }
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

EXPECTED_RESPONSE_404_ERROR = {
    "errors": [
        {
            "code": "not found",
            "message": "The Microsoft Defender "
                       "ATP not found the requested resource.",
            "type": "fatal"
        }
    ]
}

EXPECTED_RESPONSE_500_ERROR = {
    "errors": [
        {
            "code": "internal error",
            "message": "The Microsoft Defender ATP internal error.",
            "type": "fatal"
        }
    ]
}
