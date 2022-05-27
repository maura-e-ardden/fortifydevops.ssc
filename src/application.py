#+++++++++++++++ MODULE IMPORT DECLARATIONS +++++++++++++++++
from fortifydevops.fod.constants import ENUM_FOD_URL
from pip._vendor.requests.exceptions import HTTPError
from fortifydevops.fod.util import print_roundtrip, call_dump_json
from email._header_value_parser import Parameter
import time 


# from com.fortify.fod.fodapi.util import print_roundtrip
# ++++ Function get_fod_application_by_name +++++++++++++++
# 
# Purpose: Return the Id of the last static scan of a given release
#
# Signature: _get_fod_sast_last_scan_by_releaseid(token, releaseId)
#
# Parameters: 
#        token: <String> - A valid bearer token
#        releaseId: <Long> - Unique identifier of a release
#
#+++++++++++++++++++++++++++++++++++++++++++++++++++++++
# Retrieve previous (latest) release
# A new release demands a transfer of any active vulnerabilities and their latest state 
# from the previous release. This routine identifies such previous release 
# will create both.
#
# Assert the existence of the application record in FoD

def get_fod_application_by_name(session, token, applicationName):
    
    # configure query string
    parameterString = {'filters':'applicationName:' + applicationName, 
                       'fields':'applicationName,applicationId,hasMicroservices'}
    
    # set headers
    headers = {'accept': 'application/json', 
               'authorization': 'Bearer ' + token, 
               'cache-control': 'no-cache'}
    try:
        # send the request
        response = session.get(ENUM_FOD_URL.BASE_API_V3_URL.value + 
                               '/applications',
                               params=parameterString,
                               headers=headers,
                               hooks={'response': print_roundtrip})

        
        # If the response succeeds, no Exception will be raised
        response.raise_for_status()
        
    except HTTPError as http_err:
        print(f'[Error] FoD - get_fod_application_by_name: API access error. Error is: {http_err}')
        
    except Exception as e:
        print(f'[Exception] FoD - get_fod_application_by_name: API access exception. Exception is: {e}')
        
    else:
        try:
            responseDictionary = response.json()
             
#            if responseDictionary['totalCount'] != 0:
#                if str(responseDictionary['items'][0]['applicationName']) == applicationName:
#                    return True, int(responseDictionary['items'][0]['applicationId']), responseDictionary['items'][0]['hasMicroservices']
#                else:
#                    return False, 0, False 
#            else:
#                return False, 0, False

            if responseDictionary['totalCount'] != 0:
                for item in responseDictionary['items']:     
                    if item['applicationName'] == applicationName:   
                        return True, int(item['applicationId']), item['hasMicroservices']
                    else:
                        pass
                    
                return False, 0, 0
            
            else:    
                return False, 0, 0     
    
       
        except IndexError as idx_error:
            print(f'[Warning] FoD - get_fod_application_by_name: Dictionary access error. Message is: {idx_error}')
            return False, 0, False 
        
        except Exception as e:
            print(f'[Exception] FoD - get_fod_application_by_name: Dictionary access error. Exception is: {e}')
            return False, 0, False 
        
# Assert the existence of a micro service record associated with the application in FoD
def get_fod_microservice_by_name(session, token, applicationId, microserviceName):

    # set headers
    headers = {'accept': 'application/json', 
               'authorization': 'Bearer ' + token, 
               'cache-control': 'no-cache'}
    try:
        if not applicationId:
            return False, 0, 0 
        else:
            # send the request    
            response = session.get((ENUM_FOD_URL.BASE_API_V3_URL.value + 
                                   '/applications/' + str(applicationId) + 
                                   '/microservices'),
                                   headers=headers,
                                   hooks={'response': print_roundtrip})
            
            # If the response succeeds, no Exception will be raised
            response.raise_for_status()
        
    except HTTPError as http_err:
        print(f'[Error] FoD - get_fod_microservice_by_name: API access error. Error is: {http_err}')
        
    except Exception as e:
        print(f'[Exception] FoD - get_fod_microservice_by_name: API access exception. Exception is: {e}')
        
    else:
        try:
            responseDictionary = response.json()
            if responseDictionary['totalCount'] != 0:
                for item in responseDictionary['items']:     
                    if item['microserviceName'] == microserviceName:   
                        if item['releaseId'] is None:
                            return  True, int(item['microserviceId']), 0
                        else:
                            return  True, int(item['microserviceId']), int(item['releaseId'])
                    else:
                        pass
                    
                return False, 0, 0
            
            else:    
                return False, 0, 0 
            
        except IndexError as idx_error:
            print(f'[Warning] FoD - get_fod_microservice_by_name: Dictionary access error. Message is: {idx_error}')
            return False, 0, 0
        
        except Exception as e:
            print(f'[Exception] FoD - get_fod_microservice_by_name: Dictionary access error. Exception is: {e}')
            return False, 0, 0

# Assert the existence of the release record in FoD
#def get_fod_release_by_name(session, token, applicationName, releaseName, microserviceId):
def get_fod_release_by_name(session, token, applicationId, releaseName, microserviceId):

    # configure query string

    #if microserviceId == 0 or microserviceId is None:
    #    parameterString = {'filters':'applicationName:' + applicationName + 
    #                   '+releaseName:' + releaseName,
    #                   'fields':'releaseName,releaseId,sdlcStatusType'}
    #else:
    #    parameterString = {'filters':'applicationName:' + applicationName + 
    #                   '+releaseName:' + releaseName + 
    #                   '+microserviceId:' + str(microserviceId),
    #                   'fields':'releaseName,releaseId, microserviceId, sdlcStatusType'}

    if microserviceId == 0 or microserviceId is None:
        parameterString = {'filters':'applicationId:' + str(applicationId) + 
                       '+releaseName:' + releaseName,
                       'fields':'releaseName,releaseId,sdlcStatusType'}
    else:
        parameterString = {'filters':'applicationId:' + str(applicationId) + 
                       '+releaseName:' + releaseName + 
                       '+microserviceId:' + str(microserviceId),
                       'fields':'releaseName,releaseId, microserviceId, sdlcStatusType'}
        
    # set headers
    headers = {'accept': 'application/json',
               'authorization': 'Bearer ' + token,
               'cache-control': 'no-cache'}
    
    try:
        # send the request
        response = session.get(ENUM_FOD_URL.BASE_API_V3_URL.value + 
                               '/releases',
                               params=parameterString,
                               headers=headers,
                               hooks={'response': print_roundtrip})
        
        # If the response succeeds, no Exception will be raised
        response.raise_for_status()
        
    except HTTPError as http_err:
        print(f'[Error] FoD - get_fod_release_by_name: API access error. Error is: {http_err}')
        
    except Exception as e:
        print(f'[Exception] FoD - get_fod_release_by_name: API access exception. Exception is: {e}')     
           
    else:
        try:
            
            responseDictionary = response.json() 

            if responseDictionary['totalCount'] != 0:
#        
#                if str(responseDictionary['items'][0]['releaseName']) == releaseName:
#                    return True, int(responseDictionary['items'][0]['releaseId']), str(responseDictionary['items'][0]['sdlcStatusType'])
#                else:
#                    return False, 0, 0
#            else:
#                return False, 0, 0
#
                for item in responseDictionary['items']:     
                    if item['releaseName'] == releaseName:   
                        return True, int(item['releaseId']), str(item['sdlcStatusType'])
                    else:
                        pass
                    
                return False, 0, 0
            
            else:    
                return False, 0, 0     
    
            
        except IndexError as idx_error:
            print(f'[Warning] FoD - get_fod_release_by_name: Dictionary access error. Message is: {idx_error}. Release does not exist.')
            return False, 0, 0
        
        except Exception as e:
            print(f'[Exception] FoD - get_fod_release_by_name: Dictionary access error. Exception is: {e}')
            return False, 0, 0

# Function _get_fod_last_release_by_name +++++++++++++++
#
# To ensure continuity of the vulnerability remediation efforts in FoD,
# each new release of an application requires the transfer of all 
# active vulnerabilities existing in its previous release(s).
# To do this, the vulnerability data from the last release is used
# to initialize the new release record. This feature is only applicable 
# for applications already provisioned in FoD. 
# 
# # Purpose: Return the Id of the last static scan of a given release
#
# Signature: _get_fod_last_release_by_name(token,applicationName)
# Parameters: 
#    token: <String> - A valid bearer token
#    applicationName: <String> - The name of an application already onboarded into FoD
#
#def get_fod_last_release_by_name(session, token, applicationName, microserviceId):
def get_fod_last_release_by_name(session, token, applicationId, microserviceId):
        
    # configure query string
    # parameterString = {'filters':'sdlcStatusType:development|qa|production+applicationName:' + applicationName,
    #                   'fields':'releaseId',
    #                   'orderBy':'releaseCreatedDate',
    #                   'orderByDirection':'DESC'}
    
    #parameterString = {'filters':'applicationName:' + applicationName,
    #                   'fields':'releaseId',
    #                   'orderBy':'releaseCreatedDate',
    #                   'orderByDirection':'DESC'}
    #if microserviceId == 0 or microserviceId is None:
    #    parameterString = {'filters':'applicationName:' + applicationName, 
    #                   'fields':'releaseId',
    #                   'orderBy':'releaseCreatedDate',
    #                   'orderByDirection':'DESC'}

    #else:
    #    parameterString = {'filters':'applicationName:' + applicationName + 
    #                   '+microserviceId:' + str(microserviceId),
    #                   'fields':'releaseId',
    #                   'orderBy':'releaseCreatedDate',
    #                   'orderByDirection':'DESC'}

    if microserviceId == 0 or microserviceId is None:
        parameterString = {'filters':'applicationId:' + str(applicationId), 
                       'fields':'releaseId',
                       'orderBy':'releaseCreatedDate',
                       'orderByDirection':'DESC'}

    else:
        parameterString = {'filters':'applicationId:' + str(applicationId) + 
                       '+microserviceId:' + str(microserviceId),
                       'fields':'releaseId',
                       'orderBy':'releaseCreatedDate',
                       'orderByDirection':'DESC'}


    # set headers
    headers = {'accept': 'application/json', 
               'authorization': 'Bearer ' + token, 
               'cache-control': 'no-cache'}
    try:
        # send the request
        response = session.get(ENUM_FOD_URL.BASE_API_V3_URL.value + 
                               '/releases',
                                headers=headers,
                                params=parameterString,
                                hooks={'response': print_roundtrip})

        # If the response succeeds, no Exception will be raised
        response.raise_for_status()
        
    except HTTPError as http_err:
        print(f'[Error] FoD - get_fod_last_release_by_name: API access error. Error is: {http_err}')
        
    except Exception as e:
        print(f'[Exception] FoD - get_fod_last_release_by_name: API access exception. Exception is: {e}')
        
    else:
        try:

            responseDictionary = response.json()
    
            if responseDictionary['totalCount'] != 0:       
                #Loop 
                return True, int(responseDictionary['items'][0]['releaseId'])
            
            else:
                return False, 0
            
        except IndexError as idx_error:
            print(f'[Warning] FoD - get_fod_last_release_by_name: Dictionary access error. Message is: {idx_error}')
            return False, 0
        
        except Exception as e:
            print(f'[Exception] FoD - get_fod_last_release_by_name: Dictionary access error. Exception is: {e}')
            return False, 0

#+++++++++++++++++++++++++++++++++++++++++++++++++++++++
# Create a new microservice
#
def set_fod_new_microservice(session, token, applicationId, microserviceName):
    
    # configure query string

    payload = (
        "{\"microserviceName\":\"" + str(microserviceName) + "\"}")

    # set request headers

    headers = {
        'content-type': "application/json",
        'accept': "application/json",
        'authorization': "Bearer " + token,
        'cache-control': "no-cache",
        }
    
    try:
        # send the request

        response = session.post(ENUM_FOD_URL.BASE_API_V3_URL.value + 
                                '/applications/' + str(applicationId) + '/microservices',
                                data=payload,
                                headers=headers, 
                                hooks={'response': print_roundtrip})
        
        time.sleep(30)

        # If the response succeeds, no Exception will be raised otherwise, throw the exceptions
        response.raise_for_status()
    
    except HTTPError as http_err:
        print(f'[Error] FoD - set_fod_new_microservice: API access error. Error is: {http_err}')
        
    except Exception as e:
        print(f'[Exception] FoD - set_fod_new_microservice: API access exception. Exception is: {e}')

    else:
        try:
            # return the release Id
            responseDictionary = response.json()
            
            if responseDictionary['success'] == True:     
                microserviceId = responseDictionary['microserviceId']            
                
                if microserviceId:
                    
                    microServiceExists, microserviceId, microServiceReleaseId = get_fod_microservice_by_name(session, token, applicationId, microserviceName)
                    return microServiceExists, microserviceId, microServiceReleaseId
                
                else:
                    return False, 0, 0
            else:
                return False, 0, 0
                
        
        except IndexError as idx_error:
            print(f'[Warning] FoD - set_fod_new_microservice: Dictionary access error. Message is: {idx_error}')
            return False, 0
        
        except Exception as e:
            print(f'[Exception] FoD - set_fod_new_microservice: Dictionary access error. Exception is: {e}')
            return False, 0
            
#+++++++++++++++++++++++++++++++++++++++++++++++++++++++
# Create a new application
# A new application demands an initial release. the single API call
# will create both.
#
def set_fod_new_application_and_release(session, token, ownerId, applicationName, applicationType, releaseName, releaseDescription,
                                 businessCriticalityType, sdlcStatusType, emailList, hasMicroservices):
    
    payload = ("{\"applicationName\":\"" + applicationName 
    +"\",\"applicationType\":\"" + applicationType 
    +"\",\"releaseName\":\"" + releaseName 
    +"\",\"releaseDescription\":\"" + releaseDescription 
    +"\",\"ownerId\":\"" + str(ownerId)
    +"\",\"businessCriticalityType\":\"" + businessCriticalityType 
    +"\",\"sdlcStatusType\":\"" + sdlcStatusType 
    +"\",\"emailList\":\"" + emailList   
    +"\",\"hasMicroservices\":\"" + str(hasMicroservices) + "\"}")

    headers = {
        'content-type': "application/json",
        'accept': "application/json",
        'authorization': "Bearer " + token,
        'cache-control': "no-cache"
        }
    
    try:
        # send the request
        response = session.post(ENUM_FOD_URL.BASE_API_V3_URL.value + 
                                '/applications',
                                data=payload,
                                headers=headers, 
                                hooks={'response': print_roundtrip})
        
        time.sleep(30)

        # If the response succeeds, no Exception will be raised otherwise, throw the exceptions
        response.raise_for_status()
    
    except HTTPError as http_err:
        print(f'[Error] FoD - set_fod_new_application_and_release: API access error. Error is: {http_err}')
        
    except Exception as e:
        print(f'[Exception] FoD - set_fod_new_application_and_release: API access exception. Exception is: {e}')

    else:
        try:
            # return the application Id
            responseDictionary = response.json()
            
            if responseDictionary['success'] == True:     
                
                # Retrieve new release Id
                releaseExists, releaseId, releaseSdlcStatusType = get_fod_release_by_name(session, token, applicationName, releaseName, 0)
                
                if releaseExists and responseDictionary['applicationId'] and releaseId:
                    return True, int(responseDictionary['applicationId']), int(releaseId)
                
                else:
                    return False, 0, 0
            else:
                return False, 0, 0
        
        except IndexError as idx_error:
            print(f'[Warning] FoD - set_fod_new_application_and_release: Dictionary access error. Message is: {idx_error}')
            return False, 0, 0
        
        except Exception as e:
            print(f'[Exception] FoD - set_fod_new_application_and_release: Dictionary access error. Exception is: {e}')
            return False, 0, 0

#+++++++++++++++++++++++++++++++++++++++++++++++++++++++
# Create a new release
# A new application demands an initial release. the single API call
# will create both.
#
def set_fod_new_release(session, token, applicationId, releaseName, releaseDescription, copyState,
                     copyStateReleaseId, sdlcStatusType, microserviceId):
    
    # configure query string

    payload = (
        "{\"applicationId\":\"" + str(applicationId) 
    +"\",\"releaseName\":\"" + releaseName 
    +"\",\"releaseDescription\":\"" + releaseDescription 
    +"\",\"copyState\":\"" + str(copyState) 
    +"\",\"copyStateReleaseId\":\"" + str(copyStateReleaseId) 
    +"\",\"sdlcStatusType\":\"" + sdlcStatusType 
    +"\",\"microserviceId\":\"" + str(microserviceId) + "\"}")

    # set request headers

    headers = {
        'content-type': "application/json",
        'accept': "application/json",
        'authorization': "Bearer " + token,
        'cache-control': "no-cache",
        }
    
    try:
        # send the request

        response = session.post(ENUM_FOD_URL.BASE_API_V3_URL.value + 
                                '/releases',
                                 data=payload,
                                 headers=headers,
                                 hooks={'response': print_roundtrip})

        time.sleep(30)

        
        # If the response succeeds, no Exception will be raised otherwise, throw the exceptions
        response.raise_for_status()
    
    except HTTPError as http_err:
        print(f'[Error] FoD - set_fod_new_release: API access error. Error is: {http_err}')
        
    except Exception as e:
        print(f'[Exception] FoD - set_fod_new_release: API access exception. Exception is: {e}')

    else:
        try:

            # return the release Id
            responseDictionary = response.json()
            
            if responseDictionary['success'] == True:     

                releaseId = responseDictionary['releaseId']
                if releaseId:
                    return True, int(releaseId)
                else:
                    return False, 0
            else:
                return False, 0
        
        except IndexError as idx_error:
            print(f'[Warning] FoD - set_fod_new_release: Dictionary access error. Message is: {idx_error}')
            return False, 0
        
        except Exception as e:
            print(f'[Exception] FoD - set_fod_new_release: Dictionary access error. Exception is: {e}')
            return False, 0

#+++++++++++++++++++++++++++++++++++++++++++++++++++++++
# Create a new application, microservice and release
# A new application demands an initial release. If microservices is enabled, then , a 
# microservice record is also required. Both API call will create all components
#
def set_fod_new_application_and_microservice(session, token, ownerId, applicationName, applicationType, releaseName, releaseDescription,
                                 businessCriticalityType, sdlcStatusType, emailList, hasMicroservices, microserviceName):

    payload = ("{\"applicationName\":\"" + applicationName
    +"\",\"applicationType\":\"" + applicationType 
    +"\",\"releaseName\":\"" + releaseName 
    +"\",\"releaseDescription\":\"" + releaseDescription 
    +"\",\"ownerId\":\"" + str(ownerId)
    +"\",\"businessCriticalityType\":\"" + businessCriticalityType 
    +"\",\"sdlcStatusType\":\"" + sdlcStatusType 
    +"\",\"emailList\":\"" + emailList 
    +"\",\"hasMicroservices\":\"" + str(hasMicroservices)
    +"\",\"releaseMicroserviceName\":\"" + microserviceName     
    +"\",\"microservices\":[\"" + microserviceName + "\"]}")

    headers = {
        'content-type': "application/json",
        'accept': "application/json",
        'authorization': "Bearer " + token,
        'cache-control': "no-cache"
        }

    try:
        # send the request
        response = session.post(ENUM_FOD_URL.BASE_API_V3_URL.value + 
                                '/applications',
                                data=payload,
                                headers=headers, 
                                hooks={'response': print_roundtrip})

        time.sleep(30)
        
        # If the response succeeds, no Exceptiogn will be raised otherwise, throw the exceptions
        response.raise_for_status()
    
    except HTTPError as http_err:
        print(f'[Error] FoD - set_fod_new_application_microservice_and_release: API access error. Error is: {http_err}')
        
    except Exception as e:
        print(f'[Exception] FoD - set_fod_new_application_microservice_and_release: API access exception. Exception is: {e}')

    else:
        
        try:

            responseDictionary = response.json()        
            
            # Retrieve new release Id
            #releaseExists, releaseId, releaseSdlcStatusType = get_fod_release_by_name(session, token, applicationName, releaseName)

            #if releaseExists and (responseDictionary['applicationId'] is not None) and (releaseId is not None):
            if responseDictionary['success'] == True:     

                if responseDictionary['applicationId'] is not None:
                    
                    # Retrieve new microservice Id
                    #microserviceCreateStatus, microserviceId, microServiceReleaseId = get_fod_new_microservice(session, token, int(responseDictionary['applicationId']), microserviceName)
                    microserviceExists, microserviceId, microServiceReleaseId = get_fod_microservice_by_name(session, token, responseDictionary['applicationId'], microserviceName)
                    #microServiceExists, microserviceId = get_fod_microservice_by_name(session, token, int(responseDictionary['applicationId']), microserviceName) 
                    #if microServiceExists and (microserviceId is not None):
                    if microserviceExists:
                        return True, int(responseDictionary['applicationId']), microServiceReleaseId, microserviceId 
                    else:
                        return False, 0, 0, 0
                else:
                    return False, 0, 0, 0
            else:
                return False, 0, 0, 0
        
        except IndexError as idx_error:
            print(f'[Warning] FoD - set_fod_new_application_and_release: Dictionary access error. Message is: {idx_error}')
            return False, 0, 0, 0
        
        except Exception as e:
            print(f'[Exception] FoD - set_fod_new_application_and_release: Dictionary access error. Exception is: {e}')
            return False, 0, 0, 0 

#++++++++++++++++++++++++++++++++++++++++++++++++++++++++
# Update an existing release to incude a new microservice 
#
def set_fod_update_release(session, token, releaseId, releaseName, releaseDescription, sdlcStatusType, ownerId, microserviceId):
    
    # configure query string

    payload = (
        "{\"releaseName\":\"" + releaseName 
    +"\",\"releaseDescription\":\"" + releaseDescription 
    +"\",\"sdlcStatusType\":\"" + sdlcStatusType 
    +"\",\"ownerId\":\"" + str(ownerId) 
    +"\",\"microserviceId\":\"" + str(microserviceId) + "\"}")

    # set request headers

    headers = {
        'content-type': "application/json",
        'accept': "application/json",
        'authorization': "Bearer " + token,
        'cache-control': "no-cache",
        }
    
    try:
        # send the request

        #response = session.put(ENUM_FOD_URL.BASE_API_V3_URL.value + "/releases/" + releaseId, 
        #                         data=payload,
        #                         headers=headers)


        response = session.put(ENUM_FOD_URL.BASE_API_V3_URL.value + 
                                '/releases/' + releaseId,
                                 data=payload,
                                 headers=headers,
                                 hooks={'response': print_roundtrip})

                    
        time.sleep(30)
        
        # If the response succeeds, no Exception will be raised otherwise, throw the exceptions
        response.raise_for_status()
        
    
    except HTTPError as http_err:
        print(f'[Error] FoD - set_fod_new_release: API access error. Error is: {http_err}')
        
    except Exception as e:
        print(f'[Exception] FoD - set_fod_new_release: API access exception. Exception is: {e}')

    else:
        try:
            
            # return the release Id
            responseDictionary = response.json()

            if responseDictionary['success'] == True:     

                    releaseId = responseDictionary['releaseId']
                    if releaseId is not None:
                        return True, int(releaseId)
                    
                    else:
                        return False, 0
            else:
                return False, 0
                
        
        except IndexError as idx_error:
            print(f'[Warning] FoD - set_fod_update_release: Dictionary access error. Message is: {idx_error}')
            return False, 0
        
        except Exception as e:
            print(f'[Exception] FoD - set_fod_update_release: Dictionary access error. Exception is: {e}')
            return False, 0