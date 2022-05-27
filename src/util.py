#+++++++++++++++ MODULE IMPORT DECLARATIONS +++++++++++++++++
from datetime import datetime
import json, textwrap
import sys, os, subprocess, ssl, errno 
import time 

from fortifydevops.fod.constants import ENUM_FOD_URL, M_CHUNK_SIZE, \
                                        FDI_DEFAULT_API_CONFIGURATION_FILE_NAME, \
                                        FDI_DEFAULT_API_CONFIGURATION_FILE_PATH, \
                                        FDI_DEFAULT_API_CONFIGURATION_FILE_PATH_VAR_NAME, \
                                        FDI_DEFAULT_APP_CONFIGURATION_FILE_NAME, \
                                        FDI_DEFAULT_APP_PYTHON_VERSION, \
                                        FDI_DEFAULT_APP_PYTHON_REQUIREMENTS_FILE, \
                                        ENUM_FOD_DEFAULT_ENV_VAR
                                        
from fortifydevops.fod.exceptions import genericFdiError, ErrorCodes
from pip._vendor.requests.adapters import HTTPAdapter
from pip._vendor.urllib3.poolmanager import PoolManager


#  If the environment variable CONTROL_FILE_PATH is not set then 
#  get the absolute path of the fod.loader module's starting location and
#  find the relative location (../settings/) of the  api_fortify.json control file
#  defined in the static initializer FDI_DEFAULT_API_CONFIGURATION_FILE_PATH
#
def get_fdi_apiconfig_directory():
    
    if FDI_DEFAULT_API_CONFIGURATION_FILE_PATH_VAR_NAME in os.environ:

        fdi_apiconfig_dir = str(os.path.join(os.path.expandvars(
                                os.environ.get(FDI_DEFAULT_API_CONFIGURATION_FILE_PATH_VAR_NAME)), FDI_DEFAULT_API_CONFIGURATION_FILE_NAME))        
    else:
        fdi_apiconfig_dir = str(os.path.join(get_fdi_home_directory(),FDI_DEFAULT_API_CONFIGURATION_FILE_PATH, FDI_DEFAULT_API_CONFIGURATION_FILE_NAME))
    

    return fdi_apiconfig_dir        

    
#  Get the absolute path of the fod.loader module's starting location
#
#

def get_fdi_home_directory():

    return str(os.path.dirname(os.path.realpath(sys.argv[0]))) 

#++++++++++++++++++++++++++++++++++++++++++++++++++++++
#  Validate infrastructure dependencies (additional utility software)
#  The solution will validate the existence of the software dependency by asserting the environment variables JAVA_HOME, JRE_HOME, 
#  M2_HOME, MAVEN_HOME, appregisdtry[0]['scancentralpath], appregisdtry[0]['scancentralpath]
#

def call_fdi_infrastructure_remediation(dependency):
    
    #Determine if the software dependencies java, maven and gradle exist in the target system 
    
    def assert_java(buildToolsDir):
        if os.getenv('JAVA_HOME') != "":

            if os.system(os.getenv('JAVA_HOME') + '/bin/java -version') == 0:
                pass 
            else:
                #Call java installer
                install_java(buildToolsDir)                
        else:
            #Call java installer
            install_java(buildToolsDir)                
    
    #Java installer
    def install_java(buildToolsDir):
        os.system('mkdir -p ' + buildToolsDir)
        os.system('cd ' + buildToolsDir)
        os.system('curl https://download.java.net/java/GA/jdk14.0.1/664493ef4a6946b186ff29eb326336a2/7/GPL/openjdk-14.0.1_linux-x64_bin.tar.gz --output jdk.tgz')
        os.system('tar xfpz jdk.tgz')
        os.system('chmod -R 775 ' + buildToolsDir + '/jdk-14.0.1')
        os.environ['JAVA_HOME'] = buildToolsDir + '/jdk-14.0.1'
        os.environ['PATH'] += os.pathsep + os.pathsep.join([os.getenv('JAVA_HOME') + '/bin', os.environ['PATH']])    
    
    buildToolsDir = os.getcwd() + '/build-tools'

    #Assert java installation    
    assert_java(buildToolsDir)
    
    #Assert maven installation 
    if dependency == 'mvn' and os.system('mvn -version') !=0:
        #Download and install maven
        os.system('cd ' + buildToolsDir)
        os.system('curl https://archive.apache.org/dist/maven/maven-3/3.6.2/binaries/apache-maven-3.6.2-bin.tar.gz --output maven.tgz')
        os.system('tar xfpz maven.tgz')
        if os.getenv('MAVEN_HOME') != buildToolsDir + '/apache-maven-3.6.2':
            os.environ['MAVEN_HOME'] = buildToolsDir + '/apache-maven-3.6.2'
        os.system('chmod -R 775 ' + buildToolsDir + '/apache-maven-3.6.2')
        os.system('mkdir ' + os.getcwd() + '/.m2/repository')
        os.environ['M2_REPO']= os.getcwd() + '/.m2/repository'
        os.environ['PATH'] += os.pathsep + os.pathsep.join(['M2_HOME', os.environ['PATH']])
        os.environ['PATH'] += os.pathsep + os.pathsep.join([os.getenv('MAVEN_HOME') + '/bin', os.environ['PATH']])
        #Validate install
        result = os.system('mvn -version')
        if result != 0:
            print(f'[ERROR] FDI - Could not install maven')
        else:
            pass
    else:
        pass 

    
    #Assert gradle installation
    if dependency == 'gradle' and os.system('gradle -v') !=0:
        #Download and install gradle
        command = 'curl -k -L -X GET https://services.gradle.org/distributions/gradle-6.5.1-bin.zip --output gradle.zip'
        proc = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, cwd=buildToolsDir)
        print(datetime.now(), proc.stdout.decode(), flush=True)
 
        command = 'unzip -qq gradle.zip'
        proc = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, cwd=buildToolsDir)
        print(datetime.now(), proc.stdout.decode(), flush=True)
        
        os.system('export GRADLE_HOME=' + buildToolsDir + '/gradle-6.5.1')
        os.system('export PATH=$PATH:$GRADLE_HOME/bin')
        os.system('chmod -R 775 ' + os.environ['GRADLE_HOME'])

        #command = 'gradle wrapper'
        #proc = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, cwd=os.getcwd())
        #print(datetime.now(), proc.stdout.decode(), flush=True)

        #Validate install
        result = os.system('gradle wrapper')
        if result != 0:
            print(f'[ERROR] FDI - Could not install gradle')
        else:
            pass

    else:
        pass

#+++++++++++++++++++++++++++++++++++++++++++++++++++++++
#  Open the file app_fortify.json and load its content into the "data" dictionary.
#
def get_properties(fileName):
    try:
        jsonFile = open(fileName, 'rb')
        
    except OSError as os_err:
        print(f'[ERROR] FoD - File open error: Error is: {os_err}')
        sys.exit()
        
    except Exception as e:
        print(f'[ERROR] FoD - File open error: Exception is: {e}')
        sys.exit()
        
    else:
        # return a dictionary with all the properties
        propertiesDictionary = json.load(jsonFile)
        jsonFile.close
        return propertiesDictionary

def get_fdi_properties():

    # System settings overrides 
    # 1. Application Control File overrides "Application Settings" section in the System Control File
    # 2. "Application Settings" section in the System Control File overrides "Tenant Settings" section in the System Control File
    #
    def set_fdi_overrides(override, overridden, overriddenPropertyName):
        
        #Prepare the values: eliminate double spaces, tabs, new line and carriage return characters from strings
        lcl_override = " ".join(override.split())
        lcl_overridden = " ".join(overridden.split())
        
        #Execute overrides
        #both values empty
        
        if not lcl_overridden and not lcl_override:
            print('-----------------------------------------------------------------------------------------------------------------------')
            print('[ERROR]: Property: "' + overriddenPropertyName + '" cannot be empty. Check api_fortify.json and app_fortify.json files.')
            print('-----------------------------------------------------------------------------------------------------------------------')
            raise genericFdiError(ErrorCodes.FDI_INVALID_APPLICATION_REGISTRATION_ERROR)
        #Empty override
        elif (lcl_overridden != None or lcl_overridden != "") and not lcl_override:
            pass
        #Empty overridden
        elif not lcl_overridden and lcl_override:
            lcl_overridden = lcl_override 
        #Both values non-empty
        else:
            lcl_overridden = lcl_override

        return lcl_overridden
    
    releaseName = ""
    #microserviceName = ""
        
    # Retrieve base system settings: locations of JAVA_HOME, file upload, fortify tools (scan central, fodupload)     
    api_properties = get_properties(get_fdi_apiconfig_directory())
    
    # Retrieve application release settings: release name, version, SDLC stage, business criticality          
    app_properties = get_properties(os.path.join(
                                    os.path.expandvars(api_properties['system_settings']['appControlFilePath']),
                                    FDI_DEFAULT_APP_CONFIGURATION_FILE_NAME))
    
    # Retrieve application profile from control file. The profile provides details on tenancy and subscriptions, source code locations, micro service configurations, etc.
    app_registry = [item for item in api_properties['application_settings'] if (item['applicationName'] == str(app_properties['applicationName']))]  
    
    # Match tenant settings and add to app_registry
    api_tenant = [item for item in api_properties['tenant_settings'] if (item['tenantName'] == str(app_registry[0]['tenantName']))]
    
    #Validate properties
    if not app_registry: 
        raise genericFdiError(ErrorCodes.FDI_INVALID_APPLICATION_REGISTRATION_ERROR)
    
    #if (app_properties['releaseTagVarName'] != '' and app_properties['releaseTagVarName'] in os.environ):
    #    releaseName = os.getenv(app_properties['releaseTagVarName'])
        
    if app_properties['releaseName'] != '' and not releaseName:
        releaseName = app_properties['releaseName']
    
    if not app_properties['releaseName'] and not releaseName:
        raise genericFdiError(ErrorCodes.FDI_INVALID_RELEASE_NAME)
    
    if str(app_registry[0]['dast']) == 'False' and str(app_registry[0]['sast']) == 'False':
        raise genericFdiError(ErrorCodes.FDI_INVALID_AST_OPERATIONS)
    elif str(app_registry[0]['dast']) == 'True' and str(app_registry[0]['sast']) == 'False':
        raise genericFdiError(ErrorCodes.FDI_DISABLED_DAST)
    
    if str(app_registry[0]['hasMicroservices']) == 'True':
        microserviceEnabled = True    
    else:
        microserviceEnabled = False    

    #Set tenant properties
    app_registry[0]['tenantName'] = api_tenant[0]['tenantName']
    app_registry[0]['key'] = api_tenant[0]['key']
    app_registry[0]['secret'] = api_tenant[0]['secret']
    app_registry[0]['grantType'] = api_tenant[0]['grantType']
    app_registry[0]['ownerName'] = api_tenant[0]['ownerName']
    app_registry[0]['ownerId'] = api_tenant[0]['ownerId']

    #Override properties
    #Application registry overriding Tenant-level settings
    app_registry[0]['tenantName'] = set_fdi_overrides(app_registry[0]['tenantName'], api_tenant[0]['tenantName'],'tenantName')  
    app_registry[0]['entitlementId'] = set_fdi_overrides(app_registry[0]['entitlementId'], api_tenant[0]['entitlementId'],'entitlementId')  

    #Application control file settings registry overriding global application registry settings
    #app_registry[0]['technologyStack'] = set_fdi_overrides(app_properties['technologyStack'],app_registry[0]['technologyStack'],'technologyStack')  
    #app_registry[0]['languageLevel'] = set_fdi_overrides(app_properties['languageLevel'],app_registry[0]['languageLevel'],'languageLevel')  
    #app_registry[0]['buildTool'] = set_fdi_overrides(app_properties['buildTool'],app_registry[0]['buildTool'],'buildTool')  
    #app_registry[0]['ciBuilDir'] = set_fdi_overrides(app_properties['ciBuilDir'],app_registry[0]['ciBuilDir'],'ciBuildDir')  
    #app_registry[0]['pathToBuildFile'] = set_fdi_overrides(app_properties['pathToBuildFile'],app_registry[0]['pathToBuildFile'],'pathToBuildFile')  
    #app_registry[0]['pathToSourceCode'] = set_fdi_overrides(app_properties['pathToSourceCode'],app_registry[0]['pathToSourceCode'],'pathToSourceCode')  

    return api_properties, app_properties, app_registry, releaseName, microserviceEnabled

def call_util_scancentral_packager(_scanCentralPath, buildFilePath, buildTool, phpVersion, pythonVersion, pathToPythonRequirementsFile, pathToPythonVirtualEnvironment, _pathToSourceCode, zipLocation, zipName):
    # Call scancentral.sh to package sources
    print('Call scancentral.sh to package sources')
   
    try:
        
        #Validate path variables:
        if not _pathToSourceCode: 
            pathToSourceCode = os.path.expandvars(ENUM_FOD_DEFAULT_ENV_VAR.PROJECT_DIR.value)
        else:
            pathToSourceCode = os.path.expandvars(_pathToSourceCode)
        
        if not _scanCentralPath: 
            scanCentralPath = os.path.expandvars(ENUM_FOD_DEFAULT_ENV_VAR.SCAN_CENTRAL_HOME.value) + '/bin/scancentral'
        else:
            scanCentralPath = os.path.expandvars(_scanCentralPath)

        # buildTool = 'none' is used for any build strategy that is not maven, gradle, msbuild, python, or php
        
        if buildTool.lower() == 'none': 
            command = (scanCentralPath + ' package -o ' + zipLocation + '/' + zipName + ' -bt ' + buildTool)
            
        elif buildTool.lower() in ['mvn', 'gradle', 'msbuild']:
            #if not mvn, if not msbuild, if not gradle
            #throw exception 
            
            #Implement using NuGet/Mono to support .Net?
            command = (scanCentralPath + ' package -o ' + zipLocation + '/' + zipName + ' -bt ' + buildTool + ' -bf ' + buildFilePath)
        
        elif buildTool.lower() in ['zip']:
            command = ('zip -qr ' + zipLocation + '/' + zipName + ' ' + pathToSourceCode)
        

        elif buildTool.lower() in ['python']:
            pythonCommand = ""

            #Rules:
            # pythonVersion (this argument can only be 2 or 3. No other values are permitted)
            # pathToPythonRequirementsFile (this arguments expects the path and the filename)
            # pathToPythonVirtualEnvironment (this parameter points to the location of python's virtual environment
            #
            # Ignored if providing pathToPythonVirtualEnvironment =============
            if pythonVersion: 
                pythonCommand = pythonCommand + ' --python-version ' + pythonVersion
            else:
                pythonCommand = pythonCommand + ' --python-version ' + FDI_DEFAULT_APP_PYTHON_VERSION
                
                
            if pathToPythonVirtualEnvironment:
                pythonCommand = pythonCommand + ' --python-virtual-env ' +  pathToPythonVirtualEnvironment
            
            # * Should not be set if providing virtual environment location =============
            if pathToPythonRequirementsFile:
                pythonCommand = pythonCommand + ' --python-requirements ' + pathToPythonRequirementsFile
            
            if not pathToPythonVirtualEnvironment and not pathToPythonRequirementsFile:
                pythonCommand = pythonCommand + ' --python-requirements ' + FDI_DEFAULT_APP_PYTHON_REQUIREMENTS_FILE
                                        
            if pythonCommand:
                command = (scanCentralPath + ' package -o ' + zipLocation + '/' + zipName + ' -bt none' + pythonCommand)
            else:
                raise genericFdiError(ErrorCodes.FDI_CANNOT_CREATE_SCAN_PYTHON)                
    
        elif buildTool.lower() in ['php']:
            command = (scanCentralPath + ' package -o ' + zipLocation + '/' + zipName + ' -bt none ' + ' -hv ' + phpVersion)
                    
        else:
            raise genericFdiError(ErrorCodes.FDI_CANNOT_CREATE_SCAN)
        
        
        #execute command (force a different cwd if using zip)
        if buildTool.lower() in ['zip']:
            proc = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, cwd=os.getcwd())
        else:
            proc = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, cwd=pathToSourceCode)
        
        print(command)
        print(datetime.now(), proc.stdout.decode(), flush=True)
        
        
        #remove extra build-tools and sast-tools from transfer archive
        #if pathToSourceCode == os.getcwd():
            
        print ('removing any compressed archives from to FoD transfer file:')
        command = ('zip -qd ' + zipLocation + '/' + zipName + ' "**/*/sast-include.git/**/*" "**/*/build-tools/**/*" "**/*/sast-tools/**/*" "**/*/fortifydevops*/**/*" "**/*/*FodUpload.jar" "**/*/\._FodUpload.jar"')
        print ('command: ', command)
        os.system(command)
        
        return True
                
    except Exception as e:
        print(f'[Exception] error running scan central packaging utility - Exception is: {e}')
        pass
        
def print_roundtrip(response, *args, **kwargs):
    format_headers = lambda d: '\n'.join(f'{k}: {v}' for k, v in d.items())
    print(textwrap.dedent('''
        ---------------- request ----------------
        {req.method} {req.url}
        {reqhdrs}

        {req.body}
        ---------------- response ----------------
        {res.status_code} {res.reason} {res.url}
        {reshdrs}

        {res.text}
    ''').format(
        req=response.request,
        res=response,
        reqhdrs=format_headers(response.request.headers),
        reshdrs=format_headers(response.headers),
    ))
    
def read_chunks(_inputStream):
    while True:
        data = _inputStream.read(M_CHUNK_SIZE)
        if not data:
            break
        yield data
 
# ++++ Function call_fodupload_utility +++++++++++++++
# 
# Purpose: Submit a request to execute a scan and upload the source code archive
#          for a new static scan Return the Id of the last static scan of a given release
#
# Signature: _call_fod_upload_utility(javaPath,fodUploadJarPath,zipLocation,entitlementPreference,key,secret,tenantName,releaseId)
#
# Parameters: 
#
#        javaPath: <String> - Path to a Java Runtime Environment (JRE) binary 
#        fodUploadJarPath: <String> - Path to the FodUpload.jar executable java archive
#        zipLocation: <String> - Path to the source code zip archive. FoD analyzes the source code contained in this file.   
#        entitlementPreference: <int> [FOD_ENTITLEMENT_FREQUENCY_TYPE] - Single scan or subscription. 
#        key: <String> - Credentials (API Key or user identifier)
#        secret: <String> - Credentials (API secret or user password)
#        tenantName: (String> - Name of the FoD tenant
#        releaseId: <Long> - Unique identifier of a release
#        techStack: <Long> - Identifier of a release tenantName,releaseId
#
#
#
def call_util_foduploader(javaPath, fodUploaderPath, zipLocation, zipName, entitlementPreference, key, secret, tenantName, releaseId):
    
    try:
        
        command = (javaPath + ' -jar ' + fodUploaderPath + '/FodUpload.jar' + 
                   ' -zipLocation ' + zipLocation + '/' + zipName + 
                   ' -entitlementPreferenceType ' + str(entitlementPreference) + 
                   ' -portalurl ' + ENUM_FOD_URL.BASE_UI_URL.value + 
                   ' -apiurl ' + ENUM_FOD_URL.BASE_API_URL.value + 
                   ' -apiCredentials ' + key + ' ' + secret + 
                   ' -tenantCode ' + tenantName + 
                   ' -releaseId ' + str(releaseId) +
                   ' -remdiationScanPreferenceType RemediationScanIfAvailable' + 
                   ' -inProgressScanActionType Queue' + 
                   ' -notes ' + '"This scan was automatically started by the DevOps Gitlab integration to FoD."')
        
        print('attempting archive upload')
        time.sleep(30)
        
        proc = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, cwd=zipLocation)
        print(datetime.now(), proc.stdout.decode(), flush=True)
        
        if proc.returncode == 0:
            return True
        else:
            print('retrying upload - second attempt')
            time.sleep(30)
            
            proc = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, cwd=zipLocation)
            print(datetime.now(), proc.stdout.decode(), flush=True)
            
    except (AttributeError, TypeError):
        return False

def call_dump_json(dictionary):
    print(json.dumps(dictionary, indent=4))

class TLSv12HttpAdapter(HTTPAdapter):

    def init_poolmanager(self, connections, maxsize, block=False):
        self.poolmanager = PoolManager(
            num_pools=connections, maxsize=maxsize,
            block=block, ssl_version=ssl.PROTOCOL_TLSv1_2)
