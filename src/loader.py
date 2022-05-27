from getopt import getopt, GetoptError
import sys, os, time 

from fortifydevops.fod.application import get_fod_application_by_name, \
    get_fod_release_by_name, get_fod_last_release_by_name, get_fod_microservice_by_name, set_fod_new_release, \
    set_fod_new_application_and_release, set_fod_new_application_and_microservice, \
    set_fod_new_microservice
from fortifydevops.fod.auth import get_token_bearer, get_fod_user_by_userid 
from fortifydevops.fod.constants import FOD_SDLC_STATUS_TYPE, ENUM_FOD_URL
from fortifydevops.fod.exceptions import ErrorCodes, genericFdiError, FOD_COMMAND_LINE_HELP_TEXT
from fortifydevops.fod.scan import request_sast_scan
from fortifydevops.fod.util import call_util_scancentral_packager, TLSv12HttpAdapter, call_fdi_infrastructure_remediation, get_fdi_properties

from pip._vendor.requests import Session

#++++++++++++++++++++++++ MAIN PROGRAM ++++++++++++++++++++++
#  
#    
#
# Add exception when entitlement fails (expired or whatever.. add logic to check if for app, the chosen entitlement is good)
# 

def main(argv):

    #+++++++++++++++ VARIABLE DECLARATIONS ++++++++++++++++++
    
    applicationCreateStatus = False 
    releaseCreateStatus = False 
    microserviceCreateStatus = False
    releaseExists = False
    microserviceId = 0
    releaseId = 0
    releaseSdlcStatusType = "Development"
    priorReleaseId = 0
    
    #+++++++++++++++++++++ ARGUMENT PARSING ++++++++++++++++++++++++
    # provides -help text describing the product and how to invoke it.
    #

    try:

        # Retrieve command line arguments
        opts, args = getopt(argv,'h',['help'])
        
    except GetoptError:        
        if len(opts) != 0:
            print(FOD_COMMAND_LINE_HELP_TEXT)
            sys.exit(2)
        
    if len(opts) != 0:
        for opt, arg in opts:
            if opt in ('-h', '--help'):
                print(FOD_COMMAND_LINE_HELP_TEXT)
                sys.exit(2)
            else:
                print(FOD_COMMAND_LINE_HELP_TEXT)
    
    #+++++++++++++++++++++ PROPERTY INITIALIZATION ++++++++++++++++++++++++    
    
    sys.tracebacklimit = 1000
    
    # Retrieve base system settings: locations of JAVA_HOME, file upload, fortify tools (scan central, fodupload)     
    # Retrieve application release settings: release name, version, SDLC stage, business criticality          
    # Retrieve application profile from control file. The profile provides details on tenancy and subscriptions, source code locations, micro service configurations, etc.
    #
    api_properties, app_properties, app_registry, releaseName, microserviceEnabled = get_fdi_properties()
        
    #++++++++++++++++++++++ INFRASTRUCTURE SOFTWARE VALIDATION +++++++++++++++++++++++++    

    call_fdi_infrastructure_remediation(app_properties['buildTool'])
    
    #+++++++++++++++++++++ CONNECTIVITY: Start connection factory and create a session. Same session will be in use for the duration of the interaction with FoD ++++++++++++++++++++++++   
        
    sslAdapter = TLSv12HttpAdapter()
    session = Session()
    session.mount(ENUM_FOD_URL.BASE_API_URL.value, sslAdapter)    

    
    #+++++++++++++++++++++ AUTHENTICATION: get token ++++++++++++++++++++++++   
    
    token = get_token_bearer(session,
                             os.getenv(app_registry[0]['key']),
                             os.getenv(app_registry[0]['secret']),
                             app_registry[0]['grantType'])
    
    #+++++++++++++++++++++ CONFIGURATION VALIDATION ++++++++++++++++++++++++    
    
    # Validate if owner exists
    userExists = get_fod_user_by_userid(session, token, app_registry[0]['ownerId'])
    
    
    
    
    # get the applicationId by its name
    # https://api.ams.fortify.com/api/v3/applications?filters=applicationName:<application_name>
    # and validate if application and microservices exist
    print('get_fod_application_by_name')
    applicationExists, applicationId, microserviceExists = get_fod_application_by_name(session, token, app_properties['applicationName'])

            
    time.sleep(15)
    
    # If any microservices exist then:
    
    # find all microservices associated to an application id. Filter by microservice name.
    # https://api.ams.fortify.com/api/v3/applications/<applicationId>/microservices
    # iterate through response.dictionary and match the microservice by name

    print('get_fod_microservice_by_name')
    if microserviceExists:
        microserviceExists, microserviceId, microserviceReleaseId = get_fod_microservice_by_name(session, token, applicationId, app_properties['microserviceName'])        
        print('microservice identifiers: exists? ', microserviceExists, 'Id: ', microserviceId, 'ReleaseId:', microserviceReleaseId)


    time.sleep(1)

    # find the <releaseId> for application <applicationId> where microservice <microserviceId> is found
    # https://api.ams.fortify.com/api/v3/applications/122127/releases?filters=microserviceId:<microserviceId>+releaseName:<releaseName>
    # https://api.ams.fortify.com/api/v3/applications/122127/releases?filters=microserviceId%3A3182

    print('get_fod_release_by_name')
#    releaseExists, releaseId, releaseSdlcStatusType = get_fod_release_by_name(session, token, app_properties['applicationName'], releaseName, microserviceId)
    releaseExists, releaseId, releaseSdlcStatusType = get_fod_release_by_name(session, token, applicationId, releaseName, microserviceId)
    print('release identifiers: exists? ', releaseExists, 'Id: ', releaseId, 'ReleaseStatusType:', releaseSdlcStatusType)


    time.sleep(1)

    # If microservices are NOT enabled then proceed to release:
            
    # Validate if release exists
    #releaseExists, releaseId, releaseSdlcStatusType = get_fod_release_by_name(session, token, app_properties['applicationName'], releaseName, )

    # Get prior release Id
    print('get_fod_last_release_by_name')
    #priorReleaseExists, priorReleaseId = get_fod_last_release_by_name(session, token, app_properties['applicationName'], microserviceId)
    priorReleaseExists, priorReleaseId = get_fod_last_release_by_name(session, token, applicationId, microserviceId)
    print('prior release identifiers: exists? ', priorReleaseExists, 'Id: ', priorReleaseId)
    
    time.sleep(1)

    # Get microservice Id?
    # End program and any requests to upload data if the release has been retired
    
    if (releaseSdlcStatusType) == FOD_SDLC_STATUS_TYPE.RETIRED.value:
        raise genericFdiError(ErrorCodes.FDI_INVALID_RELEASE_NAME)
    
    print('provision records')
    
    #+++++++++++++++++++++ CREATE APPLICATION, MICROSERVICE OR VERSION ++++++++++++++++++++++++   
    # 
    #
    # Create new application and release records
    if userExists and not applicationExists and not microserviceEnabled:
        print('create a new application and initial release in fod - proc 1')
        applicationCreateStatus, applicationId, releaseId = set_fod_new_application_and_release(
                                   session,
                                   token,
                                   app_registry[0]['ownerId'],
                                   app_properties['applicationName'],
                                   app_registry[0]['applicationType'],
                                   releaseName,
                                   "This is the First release recorded of this application in FoD. It was automatically created by Fortify on Demand DevOps integration",
                                   app_registry[0]['businessCriticalityType'],
                                   app_properties['sdlcStatusType'],
                                   app_registry[0]['emailList'], 
                                   False)
        if not applicationCreateStatus:
            applicationId = 0
            releaseId = 0
            raise genericFdiError(ErrorCodes.FDI_CANNOT_CREATE_APPLICATION)
        else:
            applicationExists = True 

    time.sleep(1)
    
    # Create new application, new release and new microservice records
    # [x] app does not exist : set_fod_new_application_and_microservice_and_release

    if userExists and not applicationExists and microserviceEnabled and not microserviceExists:
        print('create a new application, initial release and microservice in fod - proc 2')
        applicationCreateStatus, applicationId, releaseId, microserviceId  = set_fod_new_application_and_microservice(
                                   session,
                                   token,
                                   app_registry[0]['ownerId'],
                                   app_properties['applicationName'],
                                   app_registry[0]['applicationType'],
                                   releaseName,
                                   "This record was automatically created by Fortify on Demand DevOps integration",
                                   app_registry[0]['businessCriticalityType'],
                                   app_properties['sdlcStatusType'],
                                   app_registry[0]['emailList'], 
                                   True,
                                   app_properties['microserviceName'])
        
        if not applicationCreateStatus:
            applicationId = 0
            releaseId = 0
            applicationExists = False  
            microserviceExists = False 
            releaseExists = False 
            raise genericFdiError(ErrorCodes.FDI_CANNOT_CREATE_APPLICATION)
        else:
            applicationExists = True 
            microserviceExists = True
            releaseExists = True 
               

    time.sleep(1)

    # Create a new microservice if an application and a release already exist
    # app exists microservice does not exist release does not exist : set_fod_new_microservice --> set_fod_new_release
    #
        
    if userExists and applicationExists and microserviceEnabled and not microserviceExists: 
        print('create a new microservice for application - proc 3')
        microserviceCreateStatus, microserviceId, releaseId = set_fod_new_microservice(session, token, applicationId, app_properties['microserviceName']) 
    
        if not microserviceCreateStatus:
            microserviceId = 0
            microserviceReleaseId = 0
            microserviceExists = False 
            raise genericFdiError(ErrorCodes.FDI_CANNOT_CREATE_MICROSERVICE)
        else:
            microserviceExists = True
            releaseExists = False  
    
    time.sleep(1)

    # Create a new release record without microservice enablement using the data contained in the previous release 
    if userExists and applicationExists and not microserviceEnabled and not releaseExists and (priorReleaseExists and priorReleaseId != 0):
        print('Create a new release by copying previous release information for an application w/o microservices | proc 4')
        releaseCreateStatus, releaseId = set_fod_new_release(
                                     session,
                                     token,
                                     applicationId,
                                     releaseName,
                                     "Automatic creation of this release by the Fortify on Demand DevOps integration. Configuration copied from release Id:" + str(priorReleaseId),
                                     True,
                                     priorReleaseId,
                                     app_properties['sdlcStatusType'],
                                     -1)
        
        if not releaseCreateStatus:
            releaseId = 0
            releaseExists = False 
            raise genericFdiError(ErrorCodes.FDI_CANNOT_CREATE_RELEASE)
        else:
            releaseExists = True 
         
    time.sleep(1)

    # Create a new release and associate an existing microservice to it
    if userExists and applicationExists and microserviceEnabled and microserviceExists and not releaseExists and (priorReleaseExists and priorReleaseId != 0):       
        print('Create a new release by copying previous release information for an application with microservices | proc 5')
        releaseCreateStatus, releaseId = set_fod_new_release(
                                     session,
                                     token,
                                     applicationId,
                                     releaseName,
                                     "Automatic creation of this release by the Fortify on Demand DevOps integration. Configuration copied from release Id:" + str(priorReleaseId),
                                     True,
                                     priorReleaseId,
                                     app_properties['sdlcStatusType'],
                                     microserviceId)
       
        if not releaseCreateStatus:
            releaseId = 0
            releaseExists = False
            raise genericFdiError(ErrorCodes.FDI_CANNOT_CREATE_RELEASE)
        else:
            releaseExists = True 
      
    time.sleep(1)

    # Create a new release record with an associated microservice using the configuration provided. No prior release record exists
    if userExists and applicationExists and microserviceEnabled and microserviceExists and not releaseExists and (not priorReleaseExists or priorReleaseId == 0):       
        print('Create the first release of an application with microservices | proc 6')
        releaseCreateStatus, releaseId = set_fod_new_release(
                                     session,
                                     token,
                                     applicationId,
                                     releaseName,
                                     "This is the First release recorded of this application in FoD. It was automatically created by Fortify on Demand DevOps integration",
                                     False,
                                     0,
                                     app_properties['sdlcStatusType'],
                                     microserviceId)
       
        if not releaseCreateStatus:
            releaseId = 0
            releaseExists = False 
            raise genericFdiError(ErrorCodes.FDI_CANNOT_CREATE_RELEASE)
        else:
            releaseExists = True 

    # Create a new release record without microservices using the configuration provided. No prior release record exists
    #if userExists and applicationExists and not microserviceEnabled and not releaseExists and (not priorReleaseExists or priorReleaseId == 0):
    #    print('Create the first release of an application w/o microservices | proc 7')
    #    releaseCreateStatus, releaseId = set_fod_new_release(
    #                                 session,
    #                                 token,
    #                                 applicationId,
    #                                 releaseName,
    #                                 "This is the first release recorded of this application in FoD. It was automatically created by Fortify on Demand DevOps integration",
    #                                 False,
    #                                 0,
    #                                 app_properties['sdlcStatusType'],
    #                                 -1)
    #          
    #    if not releaseCreateStatus:
    #        releaseId = 0
    #        raise genericFdiError(ErrorCodes.FDI_CANNOT_CREATE_RELEASE)
    #    else:
    #        releaseExists = True 
    #        
    #  
    #+++++++++++++++++++++ PACKAGE AND UPLOAD SOURCE CODE ++++++++++++++++++++++++    

    # Package the source code using scan central
    print('package source code')
    
    call_util_scancentral_packager(api_properties['system_settings']['scanCentralPath'],
                                   app_properties['pathToBuildFile'],
                                   app_properties['buildTool'],
                                   app_properties['phpVersion'],
                                   app_properties['pythonVersion'],
                                   app_properties['pathToPythonRequirementsFile'],
                                   app_properties['pathToPythonVirtualEnvironment'],
                                   app_properties['pathToSourceCode'],
                                   api_properties['system_settings']['zipFilePath'],
                                   api_properties['system_settings']['zipFileName'])

    print('request scan')
    scanRequestStatus = request_sast_scan(
                                  session,
                                  token,
                                  os.getenv(app_registry[0]['key']),
                                  os.getenv(app_registry[0]['secret']),
                                  app_registry[0]['tenantName'],
                                  releaseId,
                                  microserviceEnabled,
                                  app_registry[0]['entitlementFrequency'],
                                  app_properties['technologyStack'],
                                  app_properties['languageLevel'],
                                  os.path.expandvars(api_properties['system_settings']['javaBinPath']),
                                  os.path.expandvars(api_properties['system_settings']['fodUploaderPath']),
                                  os.path.expandvars(api_properties['system_settings']['zipFilePath']),
                                  api_properties['system_settings']['zipFileName'])
        
    if not scanRequestStatus:
            raise genericFdiError(ErrorCodes.FDI_CANNOT_CREATE_SCAN)


if __name__ == "__main__":
    main(sys.argv[1:])

