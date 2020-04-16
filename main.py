from __future__ import absolute_import
from __future__ import unicode_literals

import datetime
import json
import logging
import sys
import time

from six import integer_types
from six import text_type as unicode

if len(integer_types) == 1:
    long = integer_types[0]
import flask
from google.cloud import ndb
import memorystore

sys.path.insert(0, 'includes')
from webapp_class_wrapper import wrap_webapp_class
from datavalidation import DataValidation
from GCP_return_codes import FunctionReturnCodes as RC
from error_handling import RDK
from GCP_datastore_logging import LoggingFuctions
from p1_global_settings import PostDataRules
from p1_datastores import Datastores
from p1_services import Services, TaskArguments
from datastore_functions import DatastoreFunctions as DSF


class OauthVerify(object):
    def VerifyToken(self):
        task_id = "json-requests:OauthVerify:VerifyToken"
        return_msg = 'json-requests:OauthVerify:VerifyToken: '
        debug_data = []
        authenticated = False

        call_result = self.VerifyTokenProcessRequest()
        authenticated = call_result['authenticated']
        debug_data.append(call_result)

        if call_result[RDK.success] != RC.success:
            params = {}
            for key in self.request.arguments():
                params[key] = self.request.get(key, None)

            log_class = LoggingFuctions()
            log_class.logError(call_result[RDK.success], task_id, params, None, None, call_result[RDK.return_msg],
                               call_result[RDK.debug_data], None)
            if call_result[RDK.success] == RC.failed_retry:
                self.response.set_status(500)
            elif call_result[RDK.success] == RC.input_validation_failed:
                self.response.set_status(400)
            elif call_result[RDK.success] == RC.ACL_check_failed:
                self.response.set_status(401)

        if authenticated == True:
            return {RDK.success: call_result[RDK.success], RDK.return_msg: return_msg, RDK.debug_data: debug_data,
                    'authenticated': authenticated}
        else:
            self.response.set_status(401)
            return {RDK.success: call_result[RDK.success], RDK.return_msg: return_msg, RDK.debug_data: debug_data,
                    'authenticated': authenticated}

    def VerifyTokenProcessRequest(self):
        return_msg = 'json-requests:OauthVerify:VerifyTokenProcessRequest '
        debug_data = []
        authenticated = False
        ## validate input
        client_token_id = unicode(self.request.get('p1s5_token', ''))
        user_email = unicode(self.request.get('p1s5_firebase_email', ''))

        call_result = self.checkValues([[client_token_id, True, unicode, "len>10", "len<"],
                                        [user_email, True, unicode, "email_address"]
                                        ])
        debug_data.append(call_result)
        if call_result[RDK.success] != True:
            return_msg += "input validation failed"
            return {RDK.success: RC.input_validation_failed, RDK.return_msg: return_msg, RDK.debug_data: debug_data,
                    'authenticated': authenticated}

        ##</end> validate input

        ## try to pull cached data
        current_time = time.mktime(datetime.datetime.now().timetuple())
        mem_client = memorystore.Client()
        try:
            verified_token_id = mem_client.get(user_email + "-token_id")
            verified_token_expiration = long(mem_client.get(user_email + "-token_expiration"))
        except:
            verified_token_id = None
            verified_token_expiration = 0

        logging.info("verified_token_id:" + unicode(verified_token_id) + "| client_token_id:" + unicode(
            client_token_id) + '|verified_token_expiration:' + unicode(
            verified_token_expiration) + '|current_time:' + unicode(current_time))
        tokens_match = False
        if verified_token_id and verified_token_id == client_token_id:
            tokens_match = True

        if verified_token_id and verified_token_id == client_token_id and verified_token_expiration > current_time:
            authenticated = True
            return {RDK.success: RC.success, RDK.return_msg: return_msg, RDK.debug_data: debug_data,
                    'authenticated': authenticated}
        ##</end> try to pull cached data

        ## use the external libraray to auth
        logging.info("loading VM_oauth_external")
        from WM_oauth_external import OauthExternalVerify
        external_oauth = OauthExternalVerify()
        call_result = external_oauth.VerifyTokenID(client_token_id, user_email)
        debug_data.append(call_result)
        if call_result[RDK.success] != RC.success:
            return_msg += "oauth external call failed"
            return {RDK.success: call_result[RDK.success], RDK.return_msg: return_msg, RDK.debug_data: debug_data,
                    'authenticated': authenticated}

        authenticated = call_result['authenticated']
        ##</end> use the external libraray to auth

        return {RDK.success: RC.success, RDK.return_msg: return_msg, RDK.debug_data: debug_data,
                'authenticated': authenticated}


ndb_client = ndb.Client()


def ndb_wsgi_middleware(wsgi_app):
    def middleware(environ, start_response):
        with ndb_client.context():
            return wsgi_app(environ, start_response)

    return middleware


app = flask.Flask(__name__)
app.wsgi_app = ndb_wsgi_middleware(app.wsgi_app)


class CommonPostHandler(DataValidation, OauthVerify):
    def options(self):
        self.response.headers[str('Access-Control-Allow-Headers')] = str(
            'Cache-Control, Pragma, Origin, Authorization, Content-Type, X-Requested-With')
        self.response.headers[str('Access-Control-Allow-Methods')] = str('POST')

    def post(self, *args, **kwargs):
        debug_data = []
        task_id = 'json-requests:CommonPostHandler:post'

        self.response.headers[str('Access-Control-Allow-Headers')] = str(
            'Cache-Control, Pragma, Origin, Authorization, Content-Type, X-Requested-With')
        self.response.headers[str('Access-Control-Allow-Methods')] = str('POST')

        call_result = self.VerifyToken()
        debug_data.append(call_result)
        if call_result['authenticated'] != RC.success:
            self.create_response(call_result)
            return

        call_result = self.process_request(*args, **kwargs)
        debug_data.append(call_result)
        if call_result[RDK.success] != RC.success:
            params = {}
            for key in self.request.arguments():
                params[key] = self.request.get(key, None)
            LF = LoggingFuctions()
            LF.logError(call_result[RDK.success], task_id, params, None, None,
                        call_result[RDK.return_msg], call_result)

        self.create_response(call_result)

    def create_response(self, call_result):
        if call_result[RDK.success] == RC.success:
            self.create_success_response(call_result)
        else:
            self.create_error_response(call_result)

    def create_success_response(self, call_result):
        self.response.set_status(204)

    def create_error_response(self, call_result):
        if call_result[RDK.success] == RC.failed_retry:
            self.response.set_status(500)
        elif call_result[RDK.success] == RC.input_validation_failed:
            self.response.set_status(400)
        elif call_result[RDK.success] == RC.ACL_check_failed:
            self.response.set_status(401)

        self.response.out.write(call_result[RDK.return_msg])

    def is_admin_user_uid(self, user_uid):
        task_id = 'json-requests:CommonPostHandler:is_admin_user_uid'
        return_msg = task_id + ": "
        debug_data = []
        admin = False

        key = ndb.Key(Datastores.admin._get_kind(), user_uid)
        call_result = DSF.kget(key)
        debug_data.append(call_result)
        if call_result[RDK.success] != RC.success:
            return_msg += "Failed to load admin data from datastore"
            return {
                RDK.success: call_result[RDK.success], RDK.return_msg: return_msg, RDK.debug_data: debug_data,
                'admin': admin
            }
        admin = bool(call_result['get_result'])

        return {RDK.success: RC.success, RDK.return_msg: return_msg, RDK.debug_data: debug_data, 'admin': admin}


@app.route("/p1s5t1-oauth-verify", methods=["OPTIONS", "POST"])
@wrap_webapp_class("p1s5t1-oauth-verify")
class OAuthVerifyRequest(CommonPostHandler):
    def process_request(self):
        task_id = 'json-requests:OAuthVerify:process_request'
        debug_data = []
        return_msg = task_id + ": "

        return {RDK.success: RC.success, RDK.return_msg: return_msg, RDK.debug_data: debug_data}


@app.route(Services.json_requests.get_user_profile.url, methods=["OPTIONS", "POST"])
@wrap_webapp_class(Services.json_requests.get_user_profile.name)
class GetUserProfile(CommonPostHandler):
    def create_success_response(self, call_result):
        self.response.set_status(200)
        self.response.headers['Content-Type'] = "application/json"
        self.response.out.write(json.dumps(call_result['data']))

    def process_request(self):
        task_id = 'json-requests:GetUserProfile:process_request'
        debug_data = []
        return_msg = task_id + ": "
        data = {}

        # input validation
        phone_number = unicode(self.request.get(TaskArguments.s5t1_phone_number, "")) or None
        user_uid = unicode(self.request.get(TaskArguments.s5t1_user_uid, "")) or None
        requesting_user_uid = unicode(self.request.get(TaskArguments.s5t1_requesting_user_uid, "")) or None

        call_result = self.ruleCheck([
            [phone_number, Datastores.users._rule_phone_1],
            [user_uid, PostDataRules.optional_uid],
            [requesting_user_uid, PostDataRules.optional_uid],
        ])

        debug_data.append(call_result)
        if call_result[RDK.success] != RC.success:
            return_msg += "input validation failed"
            return {
                RDK.success: RC.input_validation_failed, RDK.return_msg: return_msg, RDK.debug_data: debug_data,
                'data': data
            }

        user_uid = long(user_uid) if user_uid else None
        requesting_user_uid = long(requesting_user_uid) if requesting_user_uid else None

        if not (phone_number or user_uid):
            return_msg += "Either phone_number or user_uid must be specified"
            return {
                RDK.success: RC.input_validation_failed, RDK.return_msg: return_msg, RDK.debug_data: debug_data,
                'data': data
            }

        user = None
        if user_uid:
            key = ndb.Key(Datastores.users._get_kind(), user_uid)
            call_result = DSF.kget(key)
            debug_data.append(call_result)
            if call_result[RDK.success] != RC.success:
                return_msg += "Failed to load user from datastore"
                return {
                    RDK.success: RC.input_validation_failed, RDK.return_msg: return_msg, RDK.debug_data: debug_data,
                    'data': data
                }
            user = call_result['get_result']

        if not user:
            user_query = Datastores.users.query(Datastores.users.phone_1 == phone_number)
            call_result = DSF.kfetch(user_query)
            debug_data.append(call_result)
            if call_result[RDK.success] != RC.success:
                return_msg += "Failed to load users from datastore"
                return {
                    RDK.success: RC.input_validation_failed, RDK.return_msg: return_msg, RDK.debug_data: debug_data,
                    'data': data
                }
            users = call_result['fetch_result']
            if users:
                user = users[0]

        if not user:
            return_msg += "User not found"
            return {
                RDK.success: RC.input_validation_failed, RDK.return_msg: return_msg, RDK.debug_data: debug_data,
                'data': data
            }

        requesting_user = None
        if requesting_user_uid:
            key = ndb.Key(Datastores.users._get_kind(), requesting_user_uid)
            call_result = DSF.kget(key)
            debug_data.append(call_result)
            if call_result[RDK.success] != RC.success:
                return_msg += "Failed to load requesting user from datastore"
                return {
                    RDK.success: RC.input_validation_failed, RDK.return_msg: return_msg, RDK.debug_data: debug_data,
                    'data': data
                }
            requesting_user = call_result['get_result']
        # </end> input validation

        # check if firebase_email matches user_uid/requesting_user_uid
        firebase_email = unicode(self.request.get('p1s5_firebase_email', ''))
        if requesting_user:
            email_matches = firebase_email == requesting_user.email_address
        else:
            email_matches = firebase_email == user.email_address

        if not email_matches:
            return_msg += "firebase_email doesn't match the user_uid/requesting_user_uid"
            return {
                RDK.success: RC.input_validation_failed, RDK.return_msg: return_msg, RDK.debug_data: debug_data,
                'data': data
            }
        # </end> check if firebase_email matches user_uid/requesting_user_uid

        if requesting_user and (requesting_user_uid != user_uid):
            # check if the user is admin
            call_result = self.is_admin_user_uid(requesting_user_uid)
            debug_data.append(call_result)
            if call_result[RDK.success] != RC.success:
                return_msg += "Failed to call is_admin_user_uid"
                return {
                    RDK.success: call_result[RDK.success], RDK.return_msg: return_msg, RDK.debug_data: debug_data,
                    'data': data
                }
            if not call_result['admin']:
                return_msg += "Only admins can request the info of another user"
                return {
                    RDK.success: RC.ACL_check_failed, RDK.return_msg: return_msg, RDK.debug_data: debug_data,
                    'data': data
                }
            # </end> check if the user is admin

        # user info
        data['user'] = {
            'first_name': user.first_name or '',
            'last_name': user.last_name or '',
            'phone_1': user.phone_1 or '',
            'phone_texts': user.phone_texts or '',
            'email_address': user.email_address or '',
            'country_uid': user.country_uid or '',
            'region_uid': user.region_uid or '',
            'area_uid': user.area_uid or '',
            'description': user.description or '',
            'preferred_radius': user.preferred_radius,
            'account_flags': user.account_flags or '',
            'location_cord_lat': user.location_cords and user.location_cords.latitude,
            'location_cord_long': user.location_cords and user.location_cords.longitude,
        }
        # </end> user info

        # user skills
        skill_keys = []
        skill_info_list = []
        query = Datastores.caretaker_skills_joins.query(ancestor=user.key)
        call_result = DSF.kfetch(query)
        debug_data.append(call_result)
        if call_result[RDK.success] != RC.success:
            return_msg += "Failed to load skill_joins from datastore"
            return {
                RDK.success: call_result[RDK.success], RDK.return_msg: return_msg, RDK.debug_data: debug_data,
                'data': data
            }

        skill_joins = call_result['fetch_result']
        for skill_join in skill_joins:
            skill_info_list.append({
                'skill_uid': skill_join.skill_uid,
                'notes': skill_join.special_notes or '',
            })
            skill_keys.append(ndb.Key(Datastores.caretaker_skills._get_kind(), skill_join.skill_uid))

        call_result = DSF.kget_multi(skill_keys)
        debug_data.append(call_result)
        if call_result[RDK.success] != RC.success:
            return_msg += "Failed to load skill from datastore"
            return {
                RDK.success: call_result[RDK.success], RDK.return_msg: return_msg, RDK.debug_data: debug_data,
                'data': data
            }
        skills = call_result['get_result']
        skill_map = {}
        for skill in skills:
            skill_map[skill.key.id()] = skill
        for idx, skill_info in enumerate(skill_info_list):
            skill = skill_map[skill_info['skill_uid']]
            skill_info_list[idx].update({
                'name': skill.name,
                'description': skill.description,
            })
        data['skills'] = skill_info_list
        # </end> user skills

        # user cluster
        query = Datastores.cluster_pointer.query(ancestor=user.key)
        call_result = DSF.kfetch(query)
        debug_data.append(call_result)
        if call_result[RDK.success] != RC.success:
            return_msg += "Failed to load cluster_pointers from datastore"
            return {
                RDK.success: call_result[RDK.success], RDK.return_msg: return_msg, RDK.debug_data: debug_data,
                'data': data
            }
        cluster_pointers = call_result['fetch_result']
        data['clusters'] = [cluster_pointer.cluster_uid for cluster_pointer in cluster_pointers]
        # </end> user cluster

        # needers
        query = Datastores.needer.query(ancestor=user.key)
        call_result = DSF.kfetch(query)
        debug_data.append(call_result)
        if call_result[RDK.success] != RC.success:
            return_msg += "Failed to load needers from datastore"
            return {
                RDK.success: call_result[RDK.success], RDK.return_msg: return_msg, RDK.debug_data: debug_data,
                'data': data
            }
        needer_info_dict = {}
        need_keys = []
        needers = call_result['fetch_result']
        for needer in needers:
            query = Datastores.needer_needs_joins.query(ancestor=needer.key)
            call_result = DSF.kfetch(query)
            debug_data.append(call_result)
            if call_result[RDK.success] != RC.success:
                return_msg += "Failed to load needer_needs_joins from datastore"
                return {
                    RDK.success: call_result[RDK.success], RDK.return_msg: return_msg, RDK.debug_data: debug_data,
                    'data': data
                }
            needer_needs_joins = call_result['fetch_result']
            for needer_needs_join in needer_needs_joins:
                needer_info_dict[needer.key.id()].append({
                    "need_uid": needer_needs_join.need_uid, "notes": needer_needs_join.special_requests or ''
                })
                need_keys.append(ndb.Key(Datastores.needs._get_kind(), needer_needs_join.need_uid))

        call_result = DSF.kget_multi(need_keys)
        debug_data.append(call_result)
        if call_result[RDK.success] != RC.success:
            return_msg += "Failed to load needs from datastore"
            return {
                RDK.success: call_result[RDK.success], RDK.return_msg: return_msg, RDK.debug_data: debug_data,
                'data': data
            }
        needs = call_result['get_result']
        need_map = {}
        for need in needs:
            need_map[need.key.id()] = need

        for needer_uid in needer_info_dict:
            for idx, need_info in enumerate(needer_info_dict[needer_uid]):
                need = need_map[need_info['need_uid']]
                needer_info_dict[needer_uid][idx].update({
                    'name': need.name,
                    'description': need.requirements,
                })

        data['needers'] = needer_info_dict
        # </end> needers

        return {RDK.success: RC.success, RDK.return_msg: return_msg, RDK.debug_data: debug_data, 'data': data}


@app.route(Services.json_requests.get_cluster_data.url, methods=["OPTIONS", "POST"])
@wrap_webapp_class(Services.json_requests.get_cluster_data.name)
class GetClusterData(CommonPostHandler):
    def create_success_response(self, call_result):
        self.response.set_status(200)
        self.response.headers['Content-Type'] = "application/json"
        self.response.out.write(json.dumps(call_result['data']))

    def process_request(self):
        task_id = 'json-requests:GetClusterData:process_request'
        debug_data = []
        return_msg = task_id + ": "
        data = {}

        # input validation
        cluster_uids = unicode(self.request.get(TaskArguments.s5t2_cluster_uids, ""))

        call_result = self.ruleCheck([
            [cluster_uids, PostDataRules.required_name],
        ])
        debug_data.append(call_result)
        if call_result[RDK.success] != RC.success:
            return_msg += "input validation failed"
            return {
                RDK.success: RC.input_validation_failed, RDK.return_msg: return_msg, RDK.debug_data: debug_data,
                'data': data
            }

        try:
            cluster_uids = [long(uid.strip()) for uid in cluster_uids.split(",") if uid.strip()]
        except Exception as exc:
            return_msg += str(exc)
            return {
                RDK.success: RC.input_validation_failed, RDK.return_msg: return_msg, RDK.debug_data: debug_data,
                'data': data
            }
        # </end> input validation

        cluster_keys = [ndb.Key(Datastores.cluster._get_kind(), uid) for uid in cluster_uids]
        call_result = DSF.kget_multi(cluster_keys)
        debug_data.append(call_result)
        if call_result[RDK.success] != RC.success:
            return_msg += "Failed to load clusters from datastore"
            return {
                RDK.success: RC.input_validation_failed, RDK.return_msg: return_msg, RDK.debug_data: debug_data,
                'data': data
            }
        clusters = call_result['get_result']

        user_keys = []
        cluster_info = {}
        for idx, cluster in enumerate(clusters):
            if not cluster:
                continue

            cluster_joins_query = Datastores.cluster_joins.query(ancestor=cluster.key)
            call_result = DSF.kfetch(cluster_joins_query)
            debug_data.append(call_result)
            if call_result[RDK.success] != RC.success:
                return_msg += "Failed to load cluster joins from datastore"
                return {
                    RDK.success: RC.input_validation_failed, RDK.return_msg: return_msg, RDK.debug_data: debug_data,
                    'data': data
                }
            user_info_list = []
            needer_need_info_list = []
            cluster_joins = call_result['fetch_result']
            for cluster_join in cluster_joins:
                user_info_list.append({
                    'user_uid': cluster_join.user_uid,
                    'roles': cluster_join.roles,
                })

                user_keys.append(ndb.Key(Datastores.users._get_kind(), cluster_join.user_uid))

                needer_needs_ancestor_key = ndb.Key(
                    Datastores.users._get_kind(), cluster_join.user_uid,
                    Datastores.needer._get_kind(), cluster.needer_uid,
                )
                needer_needs_query = Datastores.needer_needs_joins.query(ancestor=needer_needs_ancestor_key)
                call_result = DSF.kfetch(needer_needs_query)
                debug_data.append(call_result)
                if call_result[RDK.success] != RC.success:
                    return_msg += "Failed to load needer needs joins from datastore"
                    return {
                        RDK.success: RC.input_validation_failed, RDK.return_msg: return_msg, RDK.debug_data: debug_data,
                        'data': data
                    }
                needer_need_joins = call_result['fetch_result']
                for needer_need_join in needer_need_joins:
                    if not needer_need_join:
                        continue

                    needer_need_info_list.append({
                        "need_uid": needer_need_join.need_uid,
                        "notes": needer_need_join.special_requests,
                    })

            cluster_info[cluster_uids[idx]] = {
                "needer_uid": cluster.needer_uid,
                "needer_needs": needer_need_info_list,
                'users': user_info_list,
            }

        call_result = DSF.kget_multi(user_keys)
        debug_data.append(call_result)
        if call_result[RDK.success] != RC.success:
            return_msg += "Failed to load users from datastore"
            return {
                RDK.success: RC.input_validation_failed, RDK.return_msg: return_msg, RDK.debug_data: debug_data,
                'data': data
            }
        users = call_result['get_result']
        user_map = {}
        for cluster_user in users:
            if not cluster_user:
                continue
            user_map[cluster_user.key.id()] = cluster_user

        for cluster_uid in cluster_info:
            for idx, user_info in enumerate(cluster_info[cluster_uid]['users']):
                cluster_user = user_map[user_info['user_uid']]
                cluster_info[cluster_uid]['users'][idx].update({
                    "name": "{} {}".format(cluster_user.first_name or '', cluster_user.last_name or '').strip(),
                    "phone_1": cluster_user.phone_1 or '',
                    "phone_2": cluster_user.phone_2 or '',
                })

        data['clusters'] = cluster_info
        return {RDK.success: RC.success, RDK.return_msg: return_msg, RDK.debug_data: debug_data, 'data': data}


@app.route(Services.json_requests.check_if_user_exists.url, methods=["OPTIONS", "POST"])
@wrap_webapp_class(Services.json_requests.check_if_user_exists.name)
class CheckIfUserExists(CommonPostHandler):
    def create_success_response(self, call_result):
        self.response.set_status(200)
        self.response.headers['Content-Type'] = "application/json"
        exists = call_result['exists']
        self.response.out.write(json.dumps({'exists': exists}))

    def process_request(self):
        task_id = 'json-requests:CheckIfUserExists:process_request'
        debug_data = []
        return_msg = task_id + ": "
        exists = False

        # input validation
        email_address = unicode(self.request.get(TaskArguments.s5t3_email_address, "")) or None
        phone_number = unicode(self.request.get(TaskArguments.s5t3_phone_number, "")) or None

        call_result = self.ruleCheck([
            [email_address, PostDataRules.optional_name],
            [phone_number, PostDataRules.optional_name],
        ])
        debug_data.append(call_result)
        if call_result[RDK.success] != RC.success:
            return_msg += "input validation failed"
            return {
                RDK.success: RC.input_validation_failed, RDK.return_msg: return_msg, RDK.debug_data: debug_data,
                'exists': exists
            }

        if not (email_address or phone_number):
            return_msg += "Email address or phone number must be specified"
            return {
                RDK.success: RC.input_validation_failed, RDK.return_msg: return_msg, RDK.debug_data: debug_data,
                'exists': exists
            }
        #</end> input validation

        if email_address and phone_number:
            user_query = Datastores.users.query(ndb.OR(
                Datastores.users.phone_1 == phone_number,
                Datastores.users.phone_2 == phone_number,
                Datastores.users.email_address == email_address,
            ))
        elif email_address:
            user_query = Datastores.users.query(Datastores.users.email_address == email_address)
        else:
            user_query = Datastores.users.query(ndb.OR(
                Datastores.users.phone_1 == phone_number, Datastores.users.phone_2 == phone_number,
            ))

        call_result = DSF.kfetch(user_query)
        debug_data.append(call_result)
        if call_result[RDK.success] != RC.success:
            return_msg += "Failed to load users from datastore"
            return {
                RDK.success: RC.input_validation_failed, RDK.return_msg: return_msg, RDK.debug_data: debug_data,
                'exists': exists,
            }
        users = call_result['fetch_result']
        if users:
            exists = True

        return {RDK.success: RC.success, RDK.return_msg: return_msg, RDK.debug_data: debug_data, 'exists': exists}


if __name__ == "__main__":
    app.run(debug=True)
