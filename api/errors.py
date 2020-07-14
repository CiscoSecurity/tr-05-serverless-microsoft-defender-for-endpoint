INVALID_REQUEST = 'invalid request'
PERMISSION_DENIED = 'permission denied'
UNKNOWN = 'unknown'
INTERNAL_SERVER_ERROR = 'internal error'
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
        if payload and payload.get('error_description'):
            message = f'Microsoft Defender ATP returned unexpected error. ' \
                      f'Details: {payload["error_description"]}'
        else:
            message = 'Something went wrong.'

        super().__init__(
            UNKNOWN,
            message=str(message)
        )


class CTRBadRequestError(CTRBaseError):
    def __init__(self, error_message=None):
        message = 'Invalid request to Microsoft Defender ATP.'
        if error_message:
            message += f' {error_message}'
        super().__init__(
            INVALID_REQUEST,
            message
        )


class CTRInternalServerError(CTRBaseError):
    def __init__(self):
        super().__init__(
            INTERNAL_SERVER_ERROR,
            'Microsoft Defender ATP internal error.'
        )


class CTRTooManyRequestsError(CTRBaseError):
    def __init__(self):
        super().__init__(
            TOO_MANY_REQUESTS,
            'Too many requests to Microsoft Defender ATP have been made. '
            'Please, try again later.'
        )
