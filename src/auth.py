#+++++++++++++++ MODULE IMPORT DECLARATIONS +++++++++++++++++
#
from fortifydevops.fod.constants import ENUM_FOD_URL, FOD_AUTH_GRANT_TYPE
from pip._vendor.requests.exceptions import HTTPError
from fortifydevops.fod.exceptions import genericFdiError, ErrorCodes

#+++++++++++++++++++++++++++++++++++++++++++++++++++++++
#  Authenticate and obtain a Bearer token
#
def get_token_bearer(session, key, secret, grantType):

    # set secrets
    payload = ""
    
    if grantType == FOD_AUTH_GRANT_TYPE.FOD_GRANT_TYPE_CLIENT_CREDENTIALS.value :
        payload = ('client_id=' + key + 
                   '&client_secret=' + secret + 
                   '&scope=api-tenant&grant_type=' + 
                   FOD_AUTH_GRANT_TYPE.FOD_GRANT_TYPE_CLIENT_CREDENTIALS.value)
    
    if grantType == FOD_AUTH_GRANT_TYPE.FOD_GRANT_TYPE_PASSWORD.value :
        payload = ('username=' + key + 
                   '&password=' + secret + 
                   '&scope=api-tenant&grant_type=' + 
                   FOD_AUTH_GRANT_TYPE.FOD_GRANT_TYPE_PASSWORD.value)
       
    # set the headers
    headers = {'cache-control': "no-cache",
               'content-type': "application/x-www-form-urlencoded"}

    try:
        # send the request
        response = session.post(ENUM_FOD_URL.AUTH_URL.value,
                                 data=payload,
                                 headers=headers)
        
        # If the response succeeds, no Exception will be raised
        response.raise_for_status()
        
    except HTTPError as http_err:
        print(f'[Error] FoD - get_token_bearer: API access error. Error is: {http_err}')
        
    except Exception as e:
        print(f'[Exception] FoD - get_token_bearer: API access exception. Exception is: {e}')
        
    else:
        try:
            # return the 'access token'
            responseDictionary = response.json()
            token = responseDictionary['access_token']
            
            if token is None or token == "":
                raise genericFdiError(ErrorCodes.FDI_INVALID_TOKEN)
            else:
                return token
        
        except IndexError as idx_error:
            print(f'[Error] FoD - get_token_bearer: Dictionary access error. Error is: {idx_error}')
            return None
        
        except Exception as e:
            print(f'[Exception] FoD - get_token_bearer: Dictionary access error. Exception is: {e}')
            return None


# Retrieve the Build Server Integration token (BSIToken) from FoD
def get_token_bsi(session, token, releaseId):

    # set headers
    
    headers = {'accept': 'application/json',
               'authorization': 'Bearer ' + token,
               'cache-control': 'no-cache'}
    
    try:
        # send the request
        response = session.post(ENUM_FOD_URL.BASE_API_V3_URL.value + 
                                '/releases/' + str(releaseId) + 
                                '/static-scan-bsi-token',
                                headers=headers)
        
        # If the response succeeds, no Exception will be raised
        response.raise_for_status()
        
    except HTTPError as http_err:
        print(f'[Error] FoD - get_token_bsi: API access error. Error is:\n {http_err}')
        
    except Exception as e:
        print(f'[Exception] FoD - get_token_bsi: API access exception. Exception is:\n {e}')
        
    else:
        try:
            responseDictionary = response.json()
            if responseDictionary['items'][0]['bsiToken'] is not None:
                return True, responseDictionary['items'][0]['bsiToken'] 
            else:
                return False, None 
            
        except IndexError as idx_error:
            print(f'[Error] FoD - get_token_bsi: Dictionary access error. Error is: {idx_error}')
            return False, None 
        
        except Exception as e:
            print(f'[Exception] FoD - get_token_bsi: Dictionary access error. Exception is: {e}')

            return False, None


#+++++++++++++++++++++++++++++++++++++++++++++++++++++++
# Assert the existence of the user owning the record in FoD
# However, the ownerId value could remain hard-coded and unchecked
# Intent is that ownerId = FoD service account
#
def get_fod_user_by_userid(session, token, ownerId):
    # configure query string
    parameterString = {'filters':"userId:" + ownerId,
                       'fields':'userId'}
    # set headers
    headers = {'accept': 'application/json',
               'authorization': 'Bearer ' + token,
               'cache-control': 'no-cache'}
    
    try:
        # send the request
        
        response = session.get(ENUM_FOD_URL.BASE_API_V3_URL.value + 
                                '/users',
                                headers=headers,
                                params=parameterString)
        
        # If the response succeeds, no Exception will be raised
        response.raise_for_status()
        
    except HTTPError as http_err:
        print(f'[Error] FoD - get_token_bsi: API access error. Error is: {http_err}')
        
    except Exception as e:
        print(f'[Exception] FoD - get_token_bsi: API access exception. Exception is: {e}')
      
    else:
        try:
            responseDictionary = response.json()
            if str(responseDictionary['items'][0]['userId']) == ownerId:
                return True
            else:
                return False
        
        except IndexError as idx_error:
            print(f'[Error] FoD - get_fod_user_by_userid: Ensure the application owner account is valid. Dictionary access error.  Error is: {idx_error}')
        
        except Exception as e:
            print(f'[Exception] FoD - get_fod_user_by_userid: Ensure the application owner account is valid. Dictionary access error. Exception is: {e}')
            return False

