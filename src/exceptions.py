from enum import Enum


# Error codes for all module exceptions
class ErrorCodes(Enum):
    FDI_INVALID_APPLICATION_REGISTRATION_ERROR = f'[WARNING] FDI - Invalid registration: This application is not registered in the master control file. Verify registration status. System exited.'
    FDI_INVALID_RELEASE_NAME = f'[ERROR] FDI - Invalid release: There is no release name or commit tag associated with this job. Verify application control file or the existence of a commit tag. System exited.'
    FDI_INVALID_RELEASE_RETIRED = f'[ERROR] FOD - Invalid release: This release has been retired in the FoD system. System exited.'
    FDI_INVALID_TOKEN = f'[ERROR] FoD - Invalid token: There was an error authenticating the operation. Please ensure the credentials are valid. System exited.'
    FDI_INVALID_AST_OPERATIONS = f'[WARNING] FDI - Invalid configuration: There is no SAST or DAST operation configured for this job. Review application control file. Nothing to do. System exited.'
    FDI_INVALID_JAVA_HOME_PATH = f'[ERROR] FDI - Invalid configuration: The location of the Java runtime could not be found. FoDUploader is a Java application and requires Java 1.8 or newer to run. '
    FDI_INVALID_ZIP_NAME = f'[ERROR] FDI - Invalid configuration: Could not submit code to FoD for analysis. The name or path of the transfer file is not valid.'    
    FDI_MISSING_DEPENDENCY = f'[ERROR] FDI - Missing infrastructure dependency: One of the following dependencies is missing: Java, Python, Gradle, Maven.' 
    FDI_DISABLED_DAST = f'[WARNING] FoD - Invalid operation: SAST operations are disable (scan setting is set to False). DAST scans are temporarily disabled. Review application control file. Nothing to do. System exited.'
    FDI_CANNOT_CREATE_APPLICATION = f'[ERROR] FoD - API: Could not create the application and its initial release.'
    FDI_CANNOT_CREATE_RELEASE = f'[ERROR] FoD - API: Could not create the release.'
    FDI_CANNOT_CREATE_MICROSERVICE = f'[ERROR] FoD - API: Could not create the microservice and its initial release.'
    FDI_CANNOT_CREATE_SCAN = f'[ERROR] FoD - API: Could not submit code to FoD for analysis. There was an error uploading the file.'   
    FDI_CANNOT_CREATE_SCAN_PYTHON = f'[ERROR] FoD - API: Could not submit Python code to FoD for analysis. There was an error packaging Python code. Ensure the name and path of the requirements file (for example, /path_to_file/requirements.txt) exists in the file system and is accurate in the control file.' 
        
# Help Messages


def helpText():
    
    helpText = ''
    helpText = helpText + 'usage: python <<client_program>>.py -h | --help\n\n'
    helpText = helpText + '       [ -h |--help] get this line of help\n\n'
    helpText = helpText + 'Fortify DevOps Integrator is a utility package, written in Python, which supports packaging and transmission of source code\n'
    helpText = helpText + 'from a pipeline to Fortify On Demand\n'
    
    return helpText


FOD_COMMAND_LINE_HELP_TEXT = helpText()

     
class genericFdiError(Exception):

    def __init__(self, exceptionMsg):

        self.error_code = exceptionMsg
        # self.traceback = sys.exc_info()
        msg = '[{0}]: {1}'.format(exceptionMsg.name, ErrorCodes(exceptionMsg).value)
    
        super().__init__(msg)
