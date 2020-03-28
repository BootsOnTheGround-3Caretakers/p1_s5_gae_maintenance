from __future__ import unicode_literals
from __future__ import absolute_import

from six import text_type as unicode
import os
import sys
import datetime
import time

cwd = os.getcwd()
sys.path.insert(0,'includes')
from datavalidation import DataValidation
from GCP_return_codes import FunctionReturnCodes as RC

#this has to be imported after sys.path.insert(0,'oauth_lib')


## google imports must be after sys.path lib is set and in this order
import google

import google.auth.transport.requests
import google.oauth2.id_token 
authHttpRequest = google.auth.transport.requests.Request
##</end> google imports must be after sys.path lib is set and in this order

import memorystore


class OauthExternalVerify(DataValidation):
    

    def VerifyTokenID(self,client_token_id,user_email):
        return_msg = 'json-requests:OauthVerify:process_request:'
        debug_data = []
        authenticated = False
        global G_DEV_FLAG
    ## validate input        
        call_result = self.checkValues([[client_token_id,True,unicode,"len>10","len<"],
                                      [user_email,True,unicode,"email_address"]
                                    ])
        debug_data.append(call_result)
        if call_result['success'] != True:
            return_msg += "input validation failed"
            return {'success': RC.input_validation_failed,'return_msg':return_msg,'debug_data':debug_data,'authenticated':authenticated}
        
    ##</end> validate input
    
    
    ## do an external check and then compare results
        firebase_key = 'aqueous-choir-160420'

        try:
            token_info = google.oauth2.id_token.verify_firebase_token(client_token_id, authHttpRequest(),firebase_key)
        except Exception as error:
            return_msg += "Exception occurred processing Token:" + str(error)
            debug_data.append([client_token_id,firebase_key])
            token_info = None
            
        if token_info == None or not token_info:
            return_msg += "no token found on server"
            return {'success': RC.ACL_check_failed,'return_msg':return_msg,'debug_data':debug_data,'authenticated':authenticated}
        
        guest_login = False
        authenticated_flag = False
        if 'provider_id' in token_info and token_info['provider_id'] == 'anonymous':
            guest_login = True
            
        if guest_login == True and user_email == "guest@watchdog.dgnet.cloud":
            authenticated_flag = True
        elif guest_login == True and user_email != "guest@watchdog.dgnet.cloud":
            return_msg += " attempt to use guest login to bypass security. "
            
        if guest_login == False and 'email' in token_info and token_info['email'] == user_email:
            authenticated_flag = True
        else:
            return_msg += "email address received from client browser and email address received from google oauth do not match. "
        
        if authenticated_flag != True:
            return_msg += " firebase auth failed, see previous messages."
            return {'success': RC.ACL_check_failed,'return_msg':return_msg,'debug_data':debug_data,'authenticated':authenticated}
    ##</end> do an external check and then compare results
        
        authenticated = True
    ## cache the new token
        
        #new tokens last 60 minutes
        verified_token_expiration = time.mktime(datetime.datetime.now().timetuple()) + 3600
        try:
            mem_client = memorystore.Client()
            mem_client.set(user_email + "-token_id",client_token_id)
            mem_client.set(user_email + "-token_expiration",verified_token_expiration)
        except Exception as e:
            return_msg += "memcache set failed with exception: %s" % unicode(e)
            return {'success': RC.memcache_failure,'return_msg':return_msg,'debug_data':debug_data,'authenticated':authenticated}
    ##</end> cache the new token
    
        return {'success': RC.success,'return_msg':return_msg,'debug_data':debug_data,'authenticated':authenticated}
