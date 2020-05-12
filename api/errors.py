import json

INVALID_ARGUMENT = 'invalid argument'
PERMISSION_DENIED = 'permission denied'
UNKNOWN = 'unknown'
NOT_FOUND = 'not found'
INTERNAL = 'internal error'


class CTRBaseError(Exception):
    def __init__(self, code, message, type_='fatal'):
        super().__init__()
        self.code = code or UNKNOWN
        self.message = message or 'Something went wrong.'
        self.type_ = type_

    @property
    def json(self):
        return {'type': self.type_,
                'code': self.code,
                'message': self.message}


class CTRInternalServerError(CTRBaseError):
    def __init__(self):
        super().__init__(
            INTERNAL,
            'The Microsoft Defender ATP internal error.'
        )


class CTRNotFoundError(CTRBaseError):
    def __init__(self):
        super().__init__(
            NOT_FOUND,
            'The Microsoft Defender ATP not found the requested resource.'
        )


class CTRInvalidCredentialsError(CTRBaseError):
    def __init__(self):
        super().__init__(
            PERMISSION_DENIED,
            'The request is missing a valid credentials.'
        )


class CTRInvalidJWTError(CTRBaseError):
    def __init__(self):
        super().__init__(
            PERMISSION_DENIED,
            'Invalid Authorization Bearer JWT.'
        )


class CTRUnexpectedResponseError(CTRBaseError):
    def __init__(self, payload):
        error_payload = json.loads(
            payload).get(
            'error', {}).get(
            'message', 'Something went wrong.')

        super().__init__(
            UNKNOWN,
            message=str(error_payload)
        )


class CTRBadRequestError(CTRBaseError):
    def __init__(self, error_message):
        super().__init__(
            INVALID_ARGUMENT,
            error_message
        )
