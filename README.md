[![Travis CI Build Status](https://travis-ci.com/CiscoSecurity/tr-05-serverless-microsoft-defender-atp.svg?branch=develop)](https://travis-ci.com/CiscoSecurity/tr-05-serverless-microsoft-defender-atp)

# Microsoft Defender ATP Relay API
[Microsoft Defender APT API](https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp)

[Create App and set permission like example](https://www.microsoft.com/en-us/videoplayer/embed/RE4d73M)

### The module requires:
 - Create an Azure Active Directory application.
 - Assign the desired permission to the application.
 - Create a key for this Application.
 - Save credentials(Tenant ID, Application ID, Application Password) for a JWT structure.

#### Permissions:
The following permissions are required to work with this module.

| Permission type                    | Permission          | Permission display name     |
|------------------------------------|---------------------|-----------------------------|
| Application                        | File.Read.All       | 'Read all file profiles'    |
| Application                        | Alert.Read.All      | 'Read all alerts'           |
| Application                        | Alert.ReadWrite.All | 'Read and write all alerts' |
| Delegated (work or school account) | File.Read.All       | 'Read all file profiles'    |
| Delegated (work or school account) | Alert.Read          | 'Read alerts'               |
| Delegated (work or school account) | Alert.ReadWrite     | 'Read and write alerts'     |

The API itself is just a simple Flask (WSGI) application which can be easily
packaged and deployed as an AWS Lambda Function working behind an AWS API
Gateway proxy using [Zappa](https://github.com/Miserlou/Zappa).

An already deployed Relay API (e.g., packaged as an AWS Lambda Function) can
be pushed to Threat Response as a Relay Module using the
[Threat Response Relay CLI](https://github.com/threatgrid/tr-lambda-relay).

## Installation

```bash
pip install -U -r requirements.txt
```

## Testing

```bash
pip install -U -r test-requirements.txt
```

- Check for *PEP 8* compliance: `flake8 .`.
- Run the suite of unit tests: `pytest -v tests/unit/`.

## Deployment

```bash
pip install -U -r deploy-requirements.txt
```

As an AWS Lambda Function:
- Deploy: `zappa deploy dev`.
- Check: `zappa status dev`.
- Update: `zappa update dev`.
- Monitor: `zappa tail dev --http`.

As a TR Relay Module:
- Create: `relay add`.
- Update: `relay edit`.
- Delete: `relay remove`.

**Note.** For convenience, each TR Relay CLI command may be prefixed with
`env $(cat .env | xargs)` to automatically read the required environment
variables from a `.env` file (i.e.`TR_API_CLIENT_ID`, `TR_API_CLIENT_PASSWORD`,
`URL`, `JWT`) and pass them to the corresponding command.

## Details
The Microsoft Defender ATP Relay API implements the following list of endpoints:
* `/observe/observables`
* `/health`

Other endpoints (`/deliberate/observables`, `/refer/observables`, `/respond/observables`, `/respond/trigger`) 
returns empty responses.

Supported types of observables:
* `ip`
* `sha1`
* `sha256`
* `domain`

Other types of observables will be ignored.

## JWT Generating

Payload for encryption must have structure:
```
{
    'client_id': <Application ID:String>,
    'client_secret': <Application Password:String>,
    'tenant_id': <Tenant ID:String>
}
```

After encryption set your `SECRET_KEY` environment 
variable in AWS lambda for successful decryption in Relay API.

## Environment Variables

- `CTR_ENTITIES_LIMIT`
  - Restricts the maximum number of CTIM entities of each type returned in a
  single response per each requested observable.
  - Applies to: `Sighting`.
  - Must be a positive integer. 
  The recommended maximum value is 1000, 
  If you use a bigger value you may hit the limit of AWS Lambda resource.
  - The default is 100 (if not installed or incorrect).

## Usage

```bash
pip install -U -r use-requirements.txt
```

```bash
export URL=<...>

http POST "${URL}"/health"
http POST "${URL}"/observe/observables" < observables.json