INVALID_REQUEST = 'invalid request'
PERMISSION_DENIED = 'permission denied'
UNKNOWN = 'unknown'
INTERNAL_SERVER_ERROR = 'internal error'
TOO_MANY_REQUESTS = 'too many requests'
AUTH_ERROR = 'authorization error'


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
    def __init__(self, error):
        if error and error.get('error_description'):
            message = f'Microsoft Defender ATP returned unexpected error. ' \
                      f'Details: {error["error_description"]}'
        else:
            message = 'Something went wrong.'

        super().__init__(
            UNKNOWN,
            message=str(message)
        )


class CTRBadRequestError(CTRBaseError):
    def __init__(self, error=None):
        message = 'Invalid request to Microsoft Defender ATP.'
        if error:
            message += f' {error}'
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
    def __init__(self, error=None):
        if '/advancedqueries/run' in error.url:
            message = f'Advanced Hunting API rate limit has been exceeded. ' \
                      f'{error.json()["error"]}'
        else:
            message = 'Too many requests to Microsoft Defender ATP ' \
                      'have been made. Please, try again later.'
        super().__init__(
            TOO_MANY_REQUESTS,
            message
        )


class CTRSSLError(CTRBaseError):
    def __init__(self, error):
        error = error.args[0].reason.args[0]
        message = getattr(error, 'verify_message', error.args[0]).capitalize()
        super().__init__(
            UNKNOWN,
            f'Unable to verify SSL certificate: {message}'
        )


class AuthorizationError(CTRBaseError):
    def __init__(self, error):

        super().__init__(
            AUTH_ERROR,
            f"Authorization failed: {error}"
        )
