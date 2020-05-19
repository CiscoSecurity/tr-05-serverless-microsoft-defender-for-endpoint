INVALID_ARGUMENT = 'invalid argument'
PERMISSION_DENIED = 'permission denied'
UNKNOWN = 'unknown'
NOT_FOUND = 'not found'
INTERNAL = 'internal error'
TOO_MANY_REQUESTS = 'too many requests'


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


class CTRInvalidCredentialsError(CTRBaseError):
    def __init__(self):
        super().__init__(
            PERMISSION_DENIED,
            'The request is missing valid credentials.'
        )


class CTRInvalidJWTError(CTRBaseError):
    def __init__(self):
        super().__init__(
            PERMISSION_DENIED,
            'Invalid Authorization Bearer JWT.'
        )


class CTRUnexpectedResponseError(CTRBaseError):
    def __init__(self, payload):
        if payload.get('error', {}).get('message'):
            message = payload['error']['message']
        else:
            message = 'Something went wrong.'

        super().__init__(
            UNKNOWN,
            message=str(message)
        )


class CTRBadRequestError(CTRBaseError):
    def __init__(self, error_message):
        super().__init__(
            INVALID_ARGUMENT,
            error_message
        )


class CTRTooManyRequestsError(CTRBaseError):
    def __init__(self):
        super().__init__(
            TOO_MANY_REQUESTS,
            'Too many requests to Microsoft Defender ATP have been made. '
            'Please, try again later.'
        )
