from flask import Flask, request, jsonify, Response,send_file
import os
import json
import random
from flask_socketio import SocketIO, send
from flask_cors import CORS, cross_origin
from werkzeug.utils import redirect, secure_filename
import base64
from requests import Request, Session
import os
from random import SystemRandom
from flasgger import Swagger

import datetime
from treelib import Tree
def formatted_time():
    now = datetime.datetime.now()
    t = f"{now.year}-{now.month:02d}-{now.day:02d} {now.hour:02d}:{now.minute:02d}:{now.second:02d}"
    return t
def time_dict():
    now = datetime.datetime.now()
    return {
        "yr": now.year,
        "mo": now.month,
        "d": now.day,
        "h": now.hour,
        "m": now.minute,
        "s": now.second,
        "z": now.microsecond
    }

import hashlib
import requests
def randomDigits(length):
    return "".join(SystemRandom().choice('123456789') for _ in range(length))
def sendMailVerifyCode(destination):
    import requests
    url = 'https://api.emailjs.com/api/v1.0/email/send'
    code = randomDigits(6)
    headers = {
        'accept': '*/*',
        'accept-language': 'zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6',
        'cache-control': 'no-cache',
        'content-type': 'application/json',
        'dnt': '1',
        'origin': 'https://dashboard.emailjs.com',
        'pragma': 'no-cache',
        'priority': 'u=1, i',
        'referer': 'https://dashboard.emailjs.com/',
        'sec-ch-ua': '"Microsoft Edge";v="129", "Not=A?Brand";v="8", "Chromium";v="129"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"macOS"',
        'sec-fetch-dest': 'empty',
        'sec-fetch-mode': 'cors',
        'sec-fetch-site': 'same-site',
        'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36 Edg/129.0.0.0'
    }
    data = {
        "lib_version": "4.4.1",
        "user_id": "your_user_id_here",
        "service_id": "your_service_id_here",
        "template_id": "template_smsverify",
        "template_params": {
            "message": f"{code}",
            "to_email": f"{destination}"
        }
    }

    response = requests.post(url,headers=headers, json=data)
    if response.status_code==200:
        return code
    return code
def save_data(dict,file='data.json'):
    try:
        with open(file, 'w', encoding='utf-8') as f:
            json.dump(dict, f, ensure_ascii=False, indent=4)
            return True
    except:
        return False
import time
def timeStamp(isInt = True):
    if isInt:
        return int(time.time()*1000)
    else:
        return time.time()*1000
def load_data(file='data.json'):

    try:
        with open(file, 'r', encoding='utf-8') as f:
            data_loaded = json.load(f)
            return data_loaded
    except FileNotFoundError:
        return {
            "action_index":0,
            "auth": {
                "OTP":{
                    "email@example.com":{
                        "code": "123456",
                        "timeCreated": 0
                    }
                },
                "sessionids":{
                    "1234567890123456":{
                        "user": "email@example.com",
                        "timeCreated": 0,
                        "lastActivity":0,
                        "accessLogs":{"time":"ip"}
                    }
                }
            },
            "email_binds":{
                "email.example.com":"lid"
            },
            "chats":{
                "channelIndex":{
                    "msgIndex":{
                        "timestamp":0,
                        "timedisplay":"2023-10-01 12:00:00",
                        "sender":"lid",
                        "content":"Hello, world!",
                        "type":"text",
                        "attachments":[]
                    }
                }
            },
            "user":{
                "lid":{
                    "sid":"lid",
                    "email":"email.example.com",
                    "pwdHash":"pwdHash",
                    "op_level":0,
                    "profile_photo_url":"https://example.com/photo.jpg"


                }
            },
            "dbWhitelist":{
                "index":["user1","user2","user3"]
            },
            "dbPermissions":{
                "index":{
                    "allowManage":10,
                    "allowRead":10,
                    "allowWrite":10
                }
            },
            "public_files":{},
            "db":{
                "index":"parameter(int float str dict list...)"
            }
        }
    except:
        return None
def getGlobalIndex():
    db = load_data()
    if "action_index" not in db:
        db["action_index"] = 0
    db["action_index"] += 1
    save_data(db)
    return db["action_index"]
def log(text_to_insert, log_file_name='actions.log',noOutput=False):
    text_to_insert = f"{formatted_time()} - {text_to_insert}"
    if not noOutput:
        print(text_to_insert)
    downloads_path = os.path.join(os.path.expanduser('~'), 'Downloads')
    #log_file_path = os.path.join(downloads_path, log_file_name)
    log_file_path = log_file_name
    if not os.path.isfile(log_file_path):
        with open(log_file_path, 'w', encoding='utf-8') as file:
            file.write(text_to_insert + '\n')
    else:
        try:
            with open(log_file_path, 'r+', encoding='utf-8') as file:
                original_lines = file.readlines()
                file.seek(0)
                file.write( text_to_insert+'\n')
                file.writelines(original_lines)
                
        except Exception as e:
            print("[ERROR storing logs]",e)
def md5Hash(text):
    return hashlib.md5(text.encode('utf-8')).hexdigest()

def executeDify(inputs, apikey="app-E3TFQMKD8Ww4igPH97YITX1C", base_url="http://xxxx.kevinwang.top/v1"):
    url = f"{base_url}/workflows/run"
    headers = {
        "Authorization": f"Bearer {apikey}",
        "Content-Type": "application/json"
    }
    payload = {
        "inputs": inputs,
        "response_mode": "streaming",
        "user": "kevinwang"
    }

    try:
        response = requests.post(url, headers=headers, json=payload)
        response.raise_for_status()
        log(f"[executeDify] Response: {response.text}")
        return response.json()
    except requests.exceptions.RequestException as e:
        log(f"[executeDify] Error: {e}")
        return json.dumps({"error": str(e)})

def pwdHash(text):
    return md5Hash(f"{text}-advx23456")
from flasgger import swag_from
app = Flask(__name__)

app.config['SWAGGER'] = {
    'title': 'API Documentation',
    'uiversion': 3,
    'openapi': '3.0.2',
    'specs_route': '/apidoc/',
    'specs': [
        {
            'endpoint': 'apispec_1',
            'route': '/apispec_1.json',
            'rule_filter': lambda rule: True,  # Optional: filter rules
            'model_filter': lambda tag: True,  # Optional: filter models
        }
    ],
    'swagger_ui': True,
    'swagger_ui_bundle_js': 'https://cdnjs.cloudflare.com/ajax/libs/swagger-ui/4.1.3/swagger-ui-bundle.js',
    'swagger_ui_bundle_css': 'https://cdnjs.cloudflare.com/ajax/libs/swagger-ui/4.1.3/swagger-ui.css',
    'swagger_ui_config': {
        'deepLinking': True,
        'displayOperationId': True,
        'defaultModelsExpandDepth': -1,  # Disable models section
        'docExpansion': 'none',  # Collapse all sections by default
        'filter': True,
        'showExtensions': True,
        'showCommonExtensions': True,
        'tryItOutEnabled': True,  # Enable "Try it out" button
    }
    
}
swagger = Swagger(app)
CORS(app, resources={r"/*": {"origins": "*"}})
socketio = SocketIO(app, cors_allowed_origins="*")
@app.route('/api/<action>', methods=['POST', 'GET'])
@cross_origin(origin='*')
@swag_from({
    "tags": ["API"],
    "parameters": [
        {
            "name": "action",
            "in": "path",
            "required": True,
            "schema": {"type": "string"},
            "description": "The action to perform, e.g., 'login', 'uploadImage', 'chat', 'database', 'getUserInfo', 'logout', 'file'."
        },
        {
            "name": "fileid",
            "in": "query",
            "required": False,
            "schema": {"type": "string"},
            "description": "The ID of the file to retrieve (only for 'file' action)."
        },
        {
            "name": "sessionid",
            "in": "cookie",
            "required": False,
            "schema": {"type": "string"},
            "description": "Session ID for user authentication."
        },
        {
            "name": "subaction",
            "in": "formData",
            "required": False,
            "schema": {"type": "string"},
            "description": "Subaction for the main action. For 'login': 'sendCode', 'otp', 'password'. For 'chat': 'send', 'receive'. For 'database': 'get', 'edit', 'add_whitelist', 'set_permission'."
        },
        {
            "name": "email",
            "in": "formData",
            "required": False,
            "schema": {"type": "string"},
            "description": "User email for login/registration."
        },
        {
            "name": "password",
            "in": "formData",
            "required": False,
            "schema": {"type": "string"},
            "description": "Password for login/registration."
        },
        {
            "name": "code",
            "in": "formData",
            "required": False,
            "schema": {"type": "string"},
            "description": "OTP code for verification."
        },
        {
            "name": "file",
            "in": "formData",
            "required": False,
            "schema": {"type": "file", "format": "binary"},
            "description": "File to upload (for uploadImage)."
        },
        {
            "name": "saveOnly",
            "in": "formData",
            "required": False,
            "schema": {"type": "boolean"},
            "description": "If true, only save the file without description (for uploadImage)."
        },
        {
            "name": "desc",
            "in": "formData",
            "required": False,
            "schema": {"type": "string"},
            "description": "Description for the uploaded file (for uploadImage)."
        },
        {
            "name": "channel",
            "in": "formData",
            "required": False,
            "schema": {"type": "string"},
            "description": "Chat channel name (for chat action)."
        },
        {
            "name": "content",
            "in": "formData",
            "required": False,
            "schema": {"type": "string"},
            "description": "Message content (for chat action)."
        },
        {
            "name": "type",
            "in": "formData",
            "required": False,
            "schema": {"type": "string"},
            "description": "Message type: 'text' or 'image' (for chat action)."
        },
        {
            "name": "image-ids",
            "in": "formData",
            "required": False,
            "schema": {"type": "array", "items": {"type": "string"}},
            "description": "List of image IDs (for chat image messages)."
        },
        {
            "name": "index",
            "in": "formData",
            "required": False,
            "schema": {"type": "string"},
            "description": "Database index key (for database action)."
        },
        {
            "name": "data",
            "in": "formData",
            "required": False,
            "schema": {"type": "string"},
            "description": "Value to save at the index (for database edit)."
        },
        {
            "name": "user",
            "in": "formData",
            "required": False,
            "schema": {"type": "string"},
            "description": "User to add to whitelist (for database add_whitelist)."
        },
        {
            "name": "allowRead",
            "in": "formData",
            "required": False,
            "schema": {"type": "integer"},
            "description": "Permission level required to read the database (for database set_permission)."
        },
        {
            "name": "allowWrite",
            "in": "formData",
            "required": False,
            "schema": {"type": "integer"},
            "description": "Permission level required to write to the database (for database set_permission)."
        },
        {
            "name": "allowManage",
            "in": "formData",
            "required": False,
            "schema": {"type": "integer"},
            "description": "Permission level required to manage the database (for database set_permission)."
        }
    ],
    "responses": {
        200: {
            "description": "Success",
            "content": {
                "application/json": {
                    "examples": {
                        "default": {
                            "message": "Operation completed successfully",
                            "status": 1
                        }
                    }
                }
            }
        },
        400: {
            "description": "Bad Request",
            "content": {
                "application/json": {
                    "examples": {
                        "default": {
                            "message": "Missing required parameters",
                            "status": 0
                        }
                    }
                }
            }
        },
        401: {
            "description": "Unauthorized",
            "content": {
                "application/json": {
                    "examples": {
                        "default": {
                            "message": "Please login first!",
                            "status": 0
                        }
                    }
                }
            }
        },
        404: {
            "description": "Not Found",
            "content": {
                "application/json": {
                    "examples": {
                        "default": {
                            "message": "User not found!",
                            "status": 0
                        }
                    }
                }
            }
        }
    }
})
def home():
    return jsonify({
        'message': 'Welcome to the API! Use /api/<action> to access different functionalities.',
        'status': 1,
        "docs": "http://xxxx.kevinwang.top:18642/apidoc"
    })
def api(action):
    db = load_data()
    
    if request.method == "GET" and action == "file":
        fileid = request.args.get('fileid', None)
        if not fileid:
            return jsonify({'message': 'File ID is required!', 'status': 0}), 400
        file_path = db['public_files'].get(fileid, None)
        if not file_path or not os.path.exists(file_path):
            return jsonify({'message': 'File not found!', 'status': 0}), 404
        try:
            return send_file(file_path, download_name=os.path.basename(file_path))
        except Exception as e:
            print(f"Error sending file: {e}")
            return jsonify({'message': 'Error sending file!', 'status': 0}), 500

    if request.method == 'GET':
        return jsonify({'message': 'GET method is not supported for this endpoint. It only indicates there is an endpoint.', 'status': 0}), 200
    lgtime = formatted_time()
    timedict = time_dict()
    timestamp_int = timeStamp(isInt=True)
    timestamp_float = timeStamp(isInt=False)
    if request.is_json:
        data = request.get_json()
    else:
        data = request.form
    cookies = {key: value for key, value in request.cookies.items()}
    sessionid = cookies.get('sessionid', None)
    # userip
    try:
        if 'X-Forwarded-For' in request.headers:
            userip = request.headers['X-Forwarded-For'].split(',')[0].strip()
        else:
            # Fallback to the direct remote address
            userip = request.remote_addr
    except Exception as e:
        print(f"Error retrieving user IP: {e}")
        userip = 'unknown'
    db = load_data()
    try:
        packetid = randomDigits(9)
        log(f'[{packetid}] [{userip}] [{lgtime}] [cookies={cookies}] {data}','incoming_requests.log',True)
    except Exception as e:
        print("Error storing logs:",e)

    print(action)
    print(data)
    if action == "login":
        print("Login action triggered.")
        if sessionid and data.get("subaction","login") == "login":
            if sessionid in db['auth']['sessionids']:
                user = db['auth']['sessionids'][sessionid]['user']
                if user in db['email_binds']:
                    print("User already logged in.")
                    resp = jsonify({'message': 'Already logged in!', 'status': 2, 'session': sessionid})
                    resp.set_cookie('sessionid', sessionid, httponly=True, samesite='Lax')
                    return resp, 200
        subAction = data.get("subaction","login")
        print(f"Subaction: {subAction}")
        if subAction == "sendCode":
            print("Sending verification code.")
            email = data.get('email')
            code = sendMailVerifyCode(email)
            db["auth"]["OTP"][email] = {
                "code": code,
                "timeCreated": timestamp_int
            }
            save_data(db)
            if code:
                return jsonify({'message':'Verification code sent!',"status":1}), 200
            return jsonify({'message':'Failed to send verification code!',"status":0}), 500
        if subAction == "otp":
            email = data.get('email')
            code = data.get('code')
            if email in db["auth"]["OTP"] and db["auth"]["OTP"][email]["code"] == code:
                time_created = db["auth"]["OTP"][email]["timeCreated"]
                if timestamp_int - time_created < 300000:
                    if email in db['email_binds']:
                        userid = db['email_binds'][email]
                        token = randomDigits(16)
                        db['auth']['sessionids'][token] = {
                        "user": email,
                        "timeCreated": timestamp_int,
                        "lastActivity": timestamp_int,
                        "accessLogs": {timestamp_int: userip}
                    }
                    else:
                        password = data.get('password',"none232984729879")
                        if password == "none232984729879":
                            return jsonify({'message':'This user does not exist. Go to register page!','status':9}), 400
                        password_hash = pwdHash(password)
                        userid = randomDigits(16)
                        db['email_binds'][email] = userid
                        db['user'][userid] = {
                            "sid": userid,
                            "pwdHash": password_hash,
                            "email": email,
                            "op_level": 0,
                            "permissions":{
                                "allowChangePwd":True,
                                "allowChangeEmail":True,
                                "allowChangeProfilePhoto":True
                            },
                            "profile_photo_url": "default_user_img.png"
                        }
                        token = randomDigits(16)
                        db['auth']['sessionids'][token] = {
                            "user": email,
                            "timeCreated": timestamp_int,
                            "lastActivity": timestamp_int,
                            "accessLogs": {timestamp_int: userip}
                        }
                        log(f"[register] [remote-addr:{userip}]  User {email} registered with password 「{password}」 and logged in successfully!")
                        status = 3
                    save_data(db)
                    resp = jsonify({'message':'OTP verified!','status':1,'session':token})
                    resp.set_cookie('sessionid', token, httponly=True, samesite='Lax')
                    return resp, 200
                return jsonify({'message':'OTP expired!','status':0}), 400
            return jsonify({'message':'Invalid OTP!','status':0}), 400
        if subAction == "password":
            print("Logging in with password.")
            email = data.get('email')
            password = data.get('password')
            if not email or not password:
                return jsonify({'message':'Email and password are required!','status':0}), 400
            password_hash = pwdHash(password)
            print("Verifying password")
            if email in db['email_binds']:
                userid = db['email_binds'][email]
                if db['user'][userid]['pwdHash'] == password_hash:
                    token = randomDigits(16)
                    db['auth']['sessionids'][token] = {
                        "user": email,
                        "timeCreated": timestamp_int,
                        "lastActivity": timestamp_int,
                        "accessLogs": {timestamp_int: userip}
                    }
                    save_data(db)
                    log(f"[login] [remote-addr:{userip}] [sessionid={token}] User {email} logged in with password {password} successfully!")
                    resp = jsonify({'message':'Login successful!','status':1,'session':token})
                    resp.set_cookie('sessionid', token, httponly=True, samesite='Lax')
                    return resp, 200
                return jsonify({'message':'Invalid password!','status':0}), 401
            return jsonify({'message':'User not found!','status':9}), 404
        
    if sessionid == None or sessionid not in db['auth']['sessionids']:
        print("Trying to redirect to login.")
        return jsonify({'message':'Please login first!','status':0}), 401
    else:
        user = db['auth']['sessionids'][sessionid]['user']
        if user not in db['email_binds']:
            return jsonify({'message':'User not found!','status':0}), 404
        db['auth']['sessionids'][sessionid]['lastActivity'] = timestamp_int
        db['auth']['sessionids'][sessionid]['accessLogs'][timestamp_int] = userip
        save_data(db)
    if action == "chat":
        subaction = data.get('subaction', 'receive')
        channel = data.get('channel', None)
        if not channel:
            return jsonify({'message': 'Channel is required!', 'status': 0}), 400
        if channel not in db['chats']['channelIndex']:
            db['chats']['channelIndex'][channel] = {}
        if subaction == 'send':
            msgIndex = getGlobalIndex()
            content = data.get('content', '')
            if not content:
                return jsonify({'message': 'Content is required!', 'status': 0}), 400
            type = data.get('type', 'text')
            if type == "text":
                db['chats']['channelIndex'][channel][msgIndex] = {
                    "timestamp": timestamp_int,
                    "timedisplay": f"{timedict['yr']}-{timedict['mo']:02d}-{timedict['d']:02d} {timedict['h']:02d}:{timedict['m']:02d}:{timedict['s']:02d}",
                    "sender": user,
                    "content": content,
                    "type": "text",
                    "attachments": []
                }
            if type == 'image':
                attachments = data.get('image-ids', [])
                if not attachments:
                    return jsonify({'message': 'Attachments are required for image type!', 'status': 0}), 400
                db['chats']['channelIndex'][channel][msgIndex] = {
                    "timestamp": timestamp_int,
                    "timedisplay": f"{timedict['yr']}-{timedict['mo']:02d}-{timedict['d']:02d} {timedict['h']:02d}:{timedict['m']:02d}:{timedict['s']:02d}",
                    "sender": user,
                    "content": content,
                    "type": "image",
                    "attachments": attachments
                }
            save_data(db)
            log(f"[chat-send] [remote-addr:{userip}] [sessionid={sessionid}] User {user} sent a message in channel '{channel}' with content: {content}")
            return jsonify({'message': 'Message sent successfully!', 'status': 1, 'msgIndex': msgIndex}), 200

    if action == "uploadImage":
        if request.method == "POST":
            if 'file' not in request.files:
                return jsonify({'message': 'No file part in the request!', 'status': 0}), 400
            file = request.files['file']
            fileid = randomDigits(23)
            saveOnly = data.get('saveOnly', False)
            if saveOnly:
                des = data.get('desc', 'This file has no description')
            else:
                res = executeDify({"image":file.read()})
                des = res["description"]

            filename = secure_filename(file.filename)
            uploads_dir = os.path.join(os.getcwd(), 'uploads')
            os.makedirs(uploads_dir, exist_ok=True)
            file_path = os.path.join(uploads_dir, filename)
            file.save(file_path)
            db = load_data()
            db["public_files"][fileid] = {
                "file_path": file_path,
                "owner":user,
                "upload_time": timestamp_int,
                "file_name": filename,
                "desc": des,
                "file_type": filename.split('.')[-1] if '.' in filename else 'unknown',
                "file_size": os.path.getsize(file_path)
            }
            save_data(db)
            return jsonify({'message': 'File uploaded successfully!', 'status': 1, 'file_path': fileid}), 200
        return jsonify({'message': 'Method not allowed!', 'status': 0}), 405

    if action == 'logout':
        if sessionid in db['auth']['sessionids']:
            del db['auth']['sessionids'][sessionid]
            save_data(db)
            log(f"[logout] [remote-addr:{userip}] [sessionid={sessionid}] User logged out successfully!")
            return jsonify({'message':'Logged out successfully!','status':1}), 200
        return jsonify({'message':'Session not found!','status':0}), 404
    
    if action == 'getUserInfo':
        if user in db['email_binds']:
            userid = db['email_binds'][user]
            user_info = db['user'].get(userid, {})
            if user_info:
                return jsonify({
                    'message': 'User info retrieved successfully!',
                    'status': 1,
                    'data': {
                        'email': user_info.get('email', ''),
                        'profile_photo_url': user_info.get('profile_photo_url', ''),
                        'op_level': user_info.get('op_level', 0),
                        'permissions': user_info.get('permissions', {})
                    }
                }), 200
            return jsonify({'message': 'User not found!', 'status': 0}), 404
        return jsonify({'message': 'Email not bound!', 'status': 0}), 404
    
    if action == "database":
        subaction = data.get('subaction', 'get')
        index = data.get('index', None)
        try:
            userOP = db['user'][db['email_binds'][user]]['op_level']
            indexOPRead = db["dbPermissions"][index]["allowRead"]
            indexOPWrite = db["dbPermissions"][index]["allowWrite"]
            indexOPManage = db["dbPermissions"][index]["allowManage"]
        except KeyError:
            indexOPRead = 0
            indexOPWrite = 0
            indexOPManage = 0
        if index is None:
            return jsonify({'message': 'Index is required!', 'status': 0}), 400
        if subaction == 'add_whitelist':
            if userOP < indexOPManage:
                return jsonify({'message': 'You do not have permission to manage this database!', 'status': 0}), 403
            new_user = data.get('user', None)
            if not new_user:
                return jsonify({'message': 'User is required!', 'status': 0}), 400
            if new_user not in db["dbWhitelist"].get(index, []):
                db["dbWhitelist"].setdefault(index, []).append(new_user)
                save_data(db)
                log(f"[database-whitelist-add] [remote-addr:{userip}] [sessionid={sessionid}] User {user} added {new_user} to database index '{index}' whitelist")
                return jsonify({'message': f'User {new_user} added to whitelist successfully!', 'status': 1}), 200
            return jsonify({'message': f'User {new_user} is already in the whitelist!', 'status': 0}), 400
        if subaction == 'set_permission':
            try:
                minOP = db["dbPermissions"][index]["allowManage"]
            except:
                db["dbPermissions"][index]["allowManage"] = minOP = 0
            if db['user'][db['email_binds'][user]]['op_level'] < minOP:
                return jsonify({'message': 'You do not have permission to manage this database!', 'status': 0}), 403
            allowRead = data.get('allowRead', db["dbPermissions"][index]["allowRead"])
            allowWrite = data.get('allowWrite', db["dbPermissions"][index]["allowWrite"])
            allowManage = data.get('allowManage', db["dbPermissions"][index]["allowManage"])
            db["dbPermissions"][index]["allowRead"] = allowRead
            db["dbPermissions"][index]["allowWrite"] = allowWrite
            db["dbPermissions"][index]["allowManage"] = allowManage
            save_data(db)
            log(f"[database-permission] [remote-addr:{userip}] [sessionid={sessionid}] User {user} set permissions for database index '{index}' to allowRead={allowRead}, allowWrite={allowWrite}, allowManage={allowManage}")
            return jsonify({'message': 'Database permissions updated successfully!', 'status': 1}), 200
        if subaction == 'get':
            if userOP < indexOPRead:
                return jsonify({'message': 'You do not have permission to read this database!', 'status': 0}), 403
            log(f"[database-get] [remote-addr:{userip}] [sessionid={sessionid}] User {user} retrieved database index '{index}'")
            return jsonify({'message': 'Database retrieved successfully!', 'status': 1, 'data': db["db"].get(index, f"Index {index} is empty.")}), 200
        elif subaction == 'edit':
            if userOP < indexOPWrite:
                return jsonify({'message': 'You do not have permission to write to this database!', 'status': 0}), 403
            new_data = data.get('data')
            if not new_data:
                return jsonify({'message': 'No data provided!', 'status': 0}), 400
            db["db"][index] = new_data
            log(f"[database-edit] [remote-addr:{userip}] [sessionid={sessionid}] User {user} overwrote database index '{index}' with data > 「{new_data}」")
            save_data(db)
            return jsonify({'message': 'Database edited successfully!', 'status': 1}), 200
        else:
            return jsonify({'message': 'Invalid action!', 'status': 0}), 400
    



if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=18642,ssl_context=('publickey.pem', 'privkey.pem'))