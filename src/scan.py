# ++++++++++++++++++ MODULE IMPORT DECLARATIONS +++++++++++++++++++
import datetime 
import sys, time 

from fortifydevops.fod.constants import ENUM_FOD_URL, FOD_ASSESSMENT_TYPE, FOD_AUDIT_PREFERENCE_TYPE, \
    FOD_ENTITLEMENT_FREQUENCY_TYPE, FOD_SCAN_TYPE
from fortifydevops.fod.util import call_util_foduploader, print_roundtrip
from pip._vendor.requests.exceptions import HTTPError


# ++++ Function get_fod_sast_plus_policy_by_releaseid +++++++++++++++
# 
# Purpose: To determine audit (Manual/Automated), assessment (Static/Static+) and 
#          remediation preferences of a scan using historic scan data 
#
# Signature: _get_fod_sast_plus_scan_by_applicationid(token, releaseId)
#
# Parameters: 
#        session: active HTTP session
#        token: <String> - A valid bearer token
#        releaseId: <Long> - Unique identifier of a release
#
# Returns:
#     status: True/False 
#     assessmentTypeId: All assessments are of type Static+
#     isRemediationScan: True or False (this value is based on a policy setting)
#     auditPreference: Manual or Automated audit (this value is based on a policy setting)
#
def get_fod_sast_plus_policy_by_releaseid(session, token, releaseId, microserviceEnabled):
    # configure query string
    parameterString = {'orderBy':'completedDateTime',
                       'orderByDirection':'DESC',
                       'fields':'releaseId,releaseName,analysisStatusType,completedDateTime,scanTypeId'
                       }
    # set headers
    headers = {'accept': 'application/json', 'authorization': 'Bearer ' + token, 'cache-control': 'no-cache'}
    try:
       
        # Iterate through all scans within a release to identify and validate 
        # [x] mandatory manual audit: every 90 days
        # [X] mandatory manual audit: first scan of each release
        # [X] mandatory non-remediation scan: first scan of each release
        # [X] mandatory non-remediation scan: one scan every 90 days
        # [X] automatic audit and remediation scans: all scans belonging to the same release with and age of <91 days
        
        # send the request
        #response = session.get(ENUM_FOD_URL.BASE_API_V3_URL.value + '/applications/' + str(applicationId) + '/scans', headers=headers, params=parameterString)
        response = session.get(ENUM_FOD_URL.BASE_API_V3_URL.value + 
                                    '/releases/' + str(releaseId) + 
                                    '/scans', 
                                    params=parameterString,
                                    headers=headers,
                                    hooks={'response': print_roundtrip})        
        
        # If the response succeeds, no Exception will be raised
        response.raise_for_status()
        
    except HTTPError as http_err:
        print(f'HTTP error occurred: {http_err}')
        sys.exit(2)
    except Exception as err:
        print(f'Other error occurred: {err}')
        sys.exit(2)
    else:
        try:
            isRemediationScan = False
            auditPreference = FOD_AUDIT_PREFERENCE_TYPE.MANUAL.value
            
            dt = datetime.date.today()
            
            responseDictionary = response.json()
            
            if responseDictionary['totalCount'] == '0':

                # This is the first static or mobile scan of this release
                # assessmentTypeId = Static+
                # isRemediation = False
                # auditPreference = Manual    
                # 
                isRemediationScan = False 
                auditPreference = FOD_AUDIT_PREFERENCE_TYPE.MANUAL.value      
                          
            else:
                               
                for item in responseDictionary['items']:                    
                        
                    if item['completedDateTime'] != None and item['analysisStatusType'] != 'In_Progress' and item['analysisStatusType'] != 'Canceled' and item['scanTypeId'] in [FOD_SCAN_TYPE.STATIC.value, FOD_SCAN_TYPE.MOBILE.value] and (dt - (datetime.datetime.strptime(item['completedDateTime'], "%Y-%m-%dT%H:%M:%S").date())).days >= 90:                        
                        # This is the 90 day manual scan review. Last scan took place 90 days ago.
                        # assessmentTypeId = Static+
                        # isRemediation = False
                        # auditPreference = Manual    
                        # completedDateTime > 3 months
                        #
                        isRemediationScan = False 
                        auditPreference = FOD_AUDIT_PREFERENCE_TYPE.MANUAL.value
                    
                    
                    elif item['completedDateTime'] != None and item['analysisStatusType'] != 'In_Progress' and item['analysisStatusType'] != 'Canceled' and item['scanTypeId'] in [FOD_SCAN_TYPE.STATIC.value, FOD_SCAN_TYPE.MOBILE.value] and (dt - (datetime.datetime.strptime(item['completedDateTime'], "%Y-%m-%dT%H:%M:%S").date())).days < 90:
                        # All scans under 90 days are:
                        # assessmentTypeId = Static+
                        # isRemediation = True
                        # auditPreference = Automated    
                        # completedDateTime < 3 months
                        #
                        isRemediationScan = True 
                        auditPreference = FOD_AUDIT_PREFERENCE_TYPE.AUTOMATED.value
                    else:
                        pass
                    
            if microserviceEnabled:
                return True, FOD_ASSESSMENT_TYPE.STATIC.value, isRemediationScan , auditPreference
                
            else:
                return True, FOD_ASSESSMENT_TYPE.STATIC_PLUS.value, isRemediationScan , auditPreference

                 
            
        except IndexError as idx_error:
            print(f'[Error] FoD - get_fod_sast_plus_policy_by_releaseid(: Dictionary access error. Error is: {idx_error}')
            return False, None, False, None
        
        except Exception as e:
            print(f'[Exception] FoD - get_fod_sast_plus_policy_by_releaseid(: There was an error while validating the scan submission policy. Please check the system configuration file and the environment variables. Exception is: {e}')
            return False, None, False, None

 
# ++++ Function _set_sast_scan_settings +++++++++++++++
# 
# Purpose: Submit a request to configure the following scan properties prior to uploading the 
#          source code archive for sast analysis:
#          Assessment Type: Static+ or Static
#          Entitlement Type: Single scan or Subscription. (Default should be subscription)
#          Technology Stack: Development language of the source code archive
#          Language Level: Version or level of the technology in stack in use
#          Perform open source code analysis using Sonatype
#          Audit preference type: Manual or Automated
#          Scan 3rd party libraries
#          Retrieve source code from a source control system
#        
def set_sast_scan_settings(session, token, releaseId, assessmentTypeId, entitlementPreference, technologyStack, languageLevel, auditPreference):

    headers = {
        'content-type':'application/json',
        'accept':'application/json',
        'authorization': 'Bearer ' + token,
        'cache-control': 'no-cache'
    }
    

    payload = (
        "{'assessmentTypeId':'" + str(assessmentTypeId) + 
        "','entitlementFrequencyType':'" + str(entitlementPreference) + 
        "','technologyStackId':'" + str(technologyStack) + 
        "','languageLevelId':'" + str(languageLevel) + 
        "','performOpenSourceAnalysis':'" + str(False) + 
        "','auditPreferenceType':'" + str(auditPreference) + 
        "','includeThirdPartyLibraries':'" + str(False) + 
        "','useSourceControl':'" + str(False) + 
        "'}")
      
    try:
                                            
        response = session.put((ENUM_FOD_URL.BASE_API_V3_URL.value + 
                                    '/releases/' + str(releaseId) + 
                                    '/static-scans/scan-setup'),
                                    data=payload,
                                    headers=headers,
                                    hooks={'response': print_roundtrip})

        time.sleep(30)

        
        # If the response succeeds, no Exception will be raised
        response.raise_for_status()
        
    except HTTPError as http_err:
        print(f'HTTP error occurred: {http_err}')
        return False
        
    except Exception as err:
        print(f'Other error occurred: {err}')
        return False 
    
    else:
        return True 


# ++++ Function request_sast_scan +++++++++++++++
# Purpose: Convenience method to requests an FoD SAST scan. The function invokes _get_fod_sast_plus_policy_by_releaseid 
#          and _call_fod_upload_utility synchronously 
# 
# Signature: request_sast_scan(token, applicationId, releaseId, javaPath, fodUploadJarPath, zipLocation, entitlementPreference, key, secret, tenantName)
#
# Parameters: 
#
#        token: <String> - A valid bearer token
#        applicationId: <Long> - Unique Identifier of an application
#        releaseId: <Long> - Unique identifier of a release
#        javaPath: <String> - Path to a Java Runtime Environment (JRE) binary 
#        fodUploadJarPath: <String> - Path to the FodUpload.jar executable java archive
#        zipLocation: <String> - Path to the source code zip archive. FoD analyzes the source code contained in this file.   
#        entitlementPreference: <Int> [FOD_ENTITLEMENT_FREQUENCY_TYPE] - Single scan or subscription. 
#        key: <String> - Credentials (API Key or user identifier)
#        secret: <String> - Credentials (API secret or user password)
#        tenantName: (String> - Name of the FoD tenant
#        releaseId: <Long> - Unique identifier of a release
#        techStack: <Long> - Identifier of a release tenantName,releaseId
#
def request_sast_scan(session, token, key, secret, tenantName, releaseId, microserviceEnabled, entitlementPreference, technologyStack, languageLevel, javaPath, fodUploaderPath, zipLocation, zipName):
    
    try:
        
        # get SAST+ policy values
        status, assessmentTypeId, isRemediationScan, auditPreference = get_fod_sast_plus_policy_by_releaseid(session, token, releaseId, microserviceEnabled)  # @UnusedVariable
        #
        if status:
                     
            if str(entitlementPreference).upper() == FOD_ENTITLEMENT_FREQUENCY_TYPE.SINGLE_SCAN.name:
                entitlementPreferenceVal = 1
            else:
                entitlementPreferenceVal = 2
            
            #Hard-coded to subscription: ensure single scan and remediation mode is not selected.
            #entitlementPreferenceVal = FOD_ENTITLEMENT_FREQUENCY_TYPE.SUBSCRIPTION.value 
            
            # set scan properties, upload source code archive and start scan
            
            if not set_sast_scan_settings(session, token,
                                    releaseId,
                                    assessmentTypeId,
                                    entitlementPreferenceVal,
                                    technologyStack,
                                    languageLevel,
                                    auditPreference):
                                    
                print(f'[Error] request_sast_scan: There was a problem executing set_sast_scan_settings')
                return False 
            
            if not call_util_foduploader(javaPath,
                                   fodUploaderPath,
                                   zipLocation,
                                   zipName,
                                   entitlementPreferenceVal,
                                   key,
                                   secret,
                                   tenantName,
                                   releaseId):  


                print(f'[Error] request_sast_scan: There was a problem executing call_util_foduploader')
                return False
           
            return True 
        
        else:
            print(f'[Error] request_sast_scan: There was a problem retrieving policy values')
            return False
        
    except Exception as e:
        print(f'Error is: {e}')
        return False
