from enum import Enum
from pip._internal import network

# constants
FDI_DEFAULT_APP_CONFIGURATION_FILE_NAME = f'app_fortify.json'
FDI_DEFAULT_API_CONFIGURATION_FILE_NAME = f'api_fortify.json'
FDI_DEFAULT_API_CONFIGURATION_FILE_PATH = f'../settings'
FDI_DEFAULT_API_CONFIGURATION_FILE_PATH_VAR_NAME = f'CONTROL_FILE_PATH'
FDI_DEFAULT_APP_PYTHON_VERSION = f'3'
FDI_DEFAULT_APP_PYTHON_REQUIREMENTS_FILE = f'./requirements.txt'


CI_COMMIT_TAG = f'CI_COMMIT_TAG'
M_CHUNK_SIZE = 1024 * 1024


# Enumerations
class FOD_AUTH_GRANT_TYPE(Enum):
    FOD_GRANT_TYPE_PASSWORD = f'password'
    FOD_GRANT_TYPE_CLIENT_CREDENTIALS = f'client_credentials'
    
    def __str__(self):
        return self.value


class FOD_ENTITLEMENT_FREQUENCY_TYPE(Enum):
    SINGLE_SCAN = 1
    SUBSCRIPTION = 2
    
    def __int__(self):
        return self.value


class FOD_ASSESSMENT_TYPE(Enum):
    STATIC_PLUS = 273
    STATIC = 274
    
    def __int__(self):
        return self.value


class FOD_AUDIT_PREFERENCE_TYPE(Enum):
    MANUAL = 1
    AUTOMATED = 2
    
    def __int__(self):
        return self.value


class FOD_SDLC_STATUS_TYPE(Enum):
    PRODUCTION = 1
    QA = 2
    DEVELOPMENT = 3
    RETIRED = 4 
    
    def __int__(self):
        return self.value

class FOD_SCAN_TYPE(Enum):
    STATIC = 1
    DYNAMIC = 2
    MOBILE = 4
    MONITORING = 5
    NETWORK = 6
    OPENSOURCE = 7
    
    def __int__(self):
        return self.value

class ENUM_FOD_URL(Enum):
    AUTH_URL = f'https://api.ams.fortify.com/oauth/token'
    BASE_API_URL = f'https://api.ams.fortify.com'
    BASE_API_V3_URI = f'/api/v3'
    BASE_API_V3_URL = f'https://api.ams.fortify.com/api/v3'
    BASE_UI_URL = f'https://ams.fortify.com'
    
    def __str__(self):
        return self.value

class ENUM_FOD_DEFAULT_ENV_VAR(Enum):
    SCAN_CENTRAL_HOME = f'$SCANCENTRAL_HOME'
    FODLOADER_HOME = f'$FODUPLOAD_HOME'
    PROJECT_DIR = f'$CI_PROJECT_DIR'
    FDI_HOME=f'$CI_PROJECT_DIR'
    CONTROL_FILE_PATH=f'$CONTROL_FILE_PATH'
    JAVA_HOME = f'$JAVA_HOME'

    
    def __str__(self):
        return self.value

