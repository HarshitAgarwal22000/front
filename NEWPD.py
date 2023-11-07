from flask import Flask, request, jsonify
from flask_cors import CORS
from functools import wraps
import requests
import MySQLdb
import jwt

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})
db = MySQLdb.connect(host='localhost', user='harshitagarwal', passwd='Anil@1973', db='powerdns_db')
cursor = db.cursor()

SECRET_KEY='DUBAI'

pdns_server = 'http://0.0.0.0:8081'
api_key = 'moscow'

def generate_jwt(uid,username):
 
        payload={"uid":uid,"username":username}
        token=jwt.encode(payload,SECRET_KEY,algorithm='HS256')
        print(token)
        return token
   
def validate(token):
    try:
        payload=jwt.decode(token,SECRET_KEY,algorithms='HS256')
        print(payload)
        return payload
    except jwt.ExpiredSignatureError:
        return None  # Token has expired
    except jwt.InvalidTokenError:
        return None  # Invalid token


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')

        if not token:
            return jsonify({'error': 'Token is missing'}), 401

        try:
            print(token)
            payloa = validate(token)
            print(payloa)
            if not payloa:
                return jsonify({'error': 'Invalid token'}), 401

            user_id = payloa['uid']
            username = payloa['username']
            return f(user_id, username, *args, **kwargs)

        except Exception as e:
            return jsonify({'error': 'Token validation error', 'details': str(e)}), 401

    return decorated


def pdns_request(method, url, data=None):
    headers = {'X-API-Key': api_key, 'Content-Type': 'application/json'}
    
    try:
        if method == 'GET':
            response = requests.get(url, headers=headers)
        elif method == 'POST':
            response = requests.post(url, headers=headers, json=data)
        elif method == 'PUT':
            response = requests.put(url, headers=headers, json=data)
        elif method == 'DELETE':
            response = requests.delete(url, headers=headers)
        elif method == 'PATCH':
            response = requests.patch(url, headers=headers, json=data)
        else:
            return jsonify({'error': 'Invalid HTTP method'}), 400
    except Exception as e:
        return jsonify({'error': 'Failed to communicate with the external service', 'details': str(e)}), 500

    if response.status_code >= 400:
        return jsonify({'error': 'External service error', 'details': response.text}), response.status_code

    return response

@app.route('/zones', methods=['GET', 'POST'])
@token_required
def manage_dns_zones(user_id,username):
    if request.method == 'GET':
       
        try:
            cursor.execute('SELECT * FROM zones')
            zones = cursor.fetchall()
            return jsonify(zones)
        except MySQLdb.Error as e:
            return jsonify({'error': 'Database error', 'details': str(e)}), 500

    if request.method == 'POST':
       
        try:
            zone_data = request.get_json()
          
            if not all(key in zone_data for key in ('zonena', 'zonemas', 'zonelastcheck', 'zonetype', 'zoneno', 'zoneaccount', 'zoneoptions', 'zonecatalog')):
                return jsonify({'error': 'Missing required fields in zone data'}), 400
        except Exception as e:
            return jsonify({'error': 'Invalid JSON data', 'details': str(e)}), 400

        query = 'INSERT INTO zones (name, master, last_check, type, notified_serial, account, options, catalog,user_id) ' \
                'VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)'
        data = (
            zone_data['zonena'], zone_data['zonemas'], zone_data['zonelastcheck'],
            zone_data['zonetype'], zone_data['zoneno'], zone_data['zoneaccount'],
            zone_data['zoneoptions'], zone_data['zonecatalog'], user_id
        )

        try:
            cursor.execute(query, data)
            db.commit()
            return jsonify({"message": "Zone added"}), 201  
        except MySQLdb.Error as e:
            return jsonify({'error': 'Database error', 'details': str(e)}), 500

@app.route('/zones/<string:zone_name>', methods=['PATCH', 'DELETE'])
@token_required
def manage_dns_zone(user_id,username,zone_name):
    if request.method == 'PATCH':
     cursor.execute('SELECT name FROM zones WHERE name = %s', (zone_name,))
     zone_exists = cursor.fetchone()
     print(zone_exists)
     if zone_exists:
        try:
            zone_data = request.get_json()
        except Exception as e:
            return jsonify({'error': 'Invalid JSON data', 'details': str(e)}), 400
        zone_name = zone_data.get('zoneName')
        key = zone_data.get('zoneDetails')
        value = zone_data.get('recorded')
        print(zone_name,key,value)
        

        try:
            cursor.execute(f"UPDATE zones SET {key}=%s WHERE name = %s",(value,zone_name))
              
            db.commit()
            print(f"Key: {key}, Value: {value}")
            return jsonify({"message": f"Zone {zone_name} has been modified"})
        except MySQLdb.Error as e:
            return jsonify({'error': 'Database error', 'details': str(e)}), 500
     else:
        
        return jsonify({"error": "Invalid Zone Name"}), 400

    if request.method == 'DELETE':
            url = f"{pdns_server}/api/v1/servers/localhost/zones/{zone_name}"
            cursor.execute('SELECT id FROM zones WHERE name = %s', (zone_name,))
            result = cursor.fetchone()
            print(result)
    
            if result is None:
                return jsonify({'error': 'Zone not found', 'details': f'Zone {zone_name} does not exist.'}), 404

            zone_id = result[0]

   
            cursor.execute('DELETE FROM dns_records where zone_id = %s', (zone_id,))
            cursor.execute('DELETE from zones where id=%s',{zone_id})
            db.commit()
    
        
            return jsonify({"message": f"Recordsin zone {zone_name} have been deleted and zone has been deleted."})

@app.route('/zones/<int:zone_id>', methods=['GET', 'POST', 'DELETE', 'PATCH'])
@token_required
def manage(user_id,username,zone_id):
    if request.method == 'GET':
     cursor.execute('SELECT id FROM zones WHERE id = %s', (zone_id,))
     zone_exists = cursor.fetchone()
     if zone_exists:
        try:
            cursor.execute(f'SELECT * FROM dns_records where zone_id ={zone_id}')
            records = cursor.fetchall()
            return jsonify(records)
        except MySQLdb.Error as e:
            return jsonify({'error': 'Database error', 'details': str(e)}), 500
     else:
        
        return jsonify({"error": "Invalid Zone ID"}), 400
    elif request.method == 'POST':
     cursor.execute('SELECT id FROM zones WHERE id = %s', (zone_id,))
     zone_exists = cursor.fetchone()
     if zone_exists:
        try:
            zone_data = request.get_json()
            zone_name = zone_data.get('zoneidr')
            zone_master = zone_data.get('zonenamr')
            zone_last_check = zone_data.get('zonelastcheckr')
            zone_type = zone_data.get('zonetyper')
            zone_no = zone_data.get('zonenor')
            zone_account = zone_data.get('zoneaccountr')
            zone_options = zone_data.get('zoneoptionsr')
        except Exception as e:
            return jsonify({'error': 'Invalid JSON data', 'details': str(e)}), 400

        query = 'INSERT INTO dns_records (zone_id, name, type, content, ttl, prio, disabled,user_id) ' \
                'VALUES (%s, %s, %s, %s, %s, %s, %s, %s)'
        data = (zone_name, zone_master, zone_last_check, zone_type, zone_no, zone_account, zone_options, user_id)

        try:
            
            cursor.execute(query, data)
            db.commit()
            return jsonify({"message": f"Records in zone {zone_id} have been added."})
        except MySQLdb.Error as e:
            return jsonify({'error': 'Database error', 'details': str(e)}), 400
     else:
        
        return jsonify({"error": "Invalid Zone ID"}), 400

    elif request.method == 'DELETE':
     cursor.execute('SELECT id FROM zones WHERE id = %s', (zone_id,))
     zone_exists = cursor.fetchone()
     if zone_exists:
        try:
            cursor.execute(f'DELETE FROM dns_records where zone_id ={zone_id} AND user_id= %s',(user_id,))
            db.commit()
            return jsonify({"message": f"Recordsin zone {zone_id} have been deleted."})
        except MySQLdb.Error as e:
            return jsonify({'error': 'Database error', 'details': str(e)}), 500
     else:
        
        return jsonify({"error": "Invalid Zone ID"}), 400

    elif request.method == 'PATCH':
     cursor.execute('SELECT id FROM zones WHERE id = %s', (zone_id,))
     zone_exist = cursor.fetchone()
     print(zone_exist)
     if zone_exist:
        try:
            zone_data = request.get_json()
            record_id = zone_data.get("recId")
            cursor.execute('SELECT id FROM dns_records WHERE id = %s', (record_id,))
            record_exist = cursor.fetchone()
            print(record_exist)
            if record_exist:
                zone_id = zone_data.get('zoneId')
                key = zone_data.get('zoneDetails')
                value = zone_data.get('recorded')
                query = f"UPDATE dns_records SET {key}=%s WHERE zone_id=%s AND id=%s"
                data = (value, zone_id, record_id)

                try:
                    cursor.execute(query, data)
                    db.commit()
                    return jsonify({"message": f"Zone {zone_id} has been modified"})
                except MySQLdb.Error as e:
                    return jsonify({'error': 'Database error', 'details': str(e)}), 500
            else:
                    return jsonify({'error': 'NO record found', 'details': str(e)}), 400
        except Exception as e:
            return jsonify({'error': 'Invalid JSON data', 'details': str(e)}), 400

        
     else:
        
        return jsonify({"error": "Invalid Zone ID"}), 400

@app.route('/zones/<int:zone_id>/<string:typer>', methods=['DELETE', 'GET'])
@token_required
def man(user_id,username,zone_id, typer):
    if request.method == 'DELETE':
     cursor.execute('SELECT id FROM zones WHERE id = %s', (zone_id,))
     zone_exists = cursor.fetchone()
     print(zone_exists)
     if zone_exists:
         print(typer)
         cursor.execute('SELECT type FROM dns_records WHERE type = %s', (typer,))
         record_exist = cursor.fetchone()
         print(record_exist)
         if record_exist:
            try:
                cursor.execute(f'DELETE FROM dns_records where zone_id =%s AND type = %s', (zone_id,typer))
                db.commit()
                return jsonify({"message": f"Records of type '{typer}' in zone {zone_id} have been deleted."})
            except MySQLdb.Error as e:
                return jsonify({'error': 'Database error', 'details': str(e)}), 400
         else:
             return jsonify({"error": "Invalid Record"}), 400
     else:
        
        return jsonify({"error": "Invalid Zone ID"}), 400

    if request.method == 'GET':
        try:
            cursor.execute(f'SELECT * FROM dns_records where zone_id={zone_id} AND type = %s', (typer,))
            reco = cursor.fetchall()
            return jsonify(reco)
        except MySQLdb.Error as e:
            return jsonify({'error': 'Database error', 'details': str(e)}), 500

@app.route('/zones/<string:typer>', methods=['GET'])
@token_required
def mans(typer):
    if request.method == 'GET':
        try:
            query  = f'SELECT * FROM dns_records where type = {typer}'
            print(query)
            cursor.execute(query)
            reco = cursor.fetchall()
            return jsonify(reco)
        except MySQLdb.Error as e:
            return jsonify({'error': 'Database error', 'details': str(e)}), 500
@app.route('/signup',methods=["POST"])
def sign_in():
    if request.method == 'POST':
        try:
             sign_up_data=request.get_json()
             print(sign_up_data)
             user=sign_up_data.get("username")
             print(user)
             p=sign_up_data.get("password")
             print(p)
             phnu=sign_up_data.get("phonenumberr")
             print(phnu)
             db = MySQLdb.connect(host='localhost', user='harshitagarwal', passwd='Anil@1973', db='powerdns_db')
             cursor = db.cursor()
             query = 'INSERT INTO users (username, password, phone_number) ' \
                'VALUES (%s, %s, %s)'
             data = (user, p, phnu)
             cursor.execute(query,data)
             user_id=cursor.lastrowid
             print(user_id)
             w=generate_jwt(user_id,user)
             print(w)
             print("HI")
             db.commit()
             return jsonify({"token":w,"message": f"Records  have been added."})
        except MySQLdb.Error as e:
            print(e)
            return jsonify({'error': 'Database error', 'details': str(e)}), 500
@app.route('/login',methods=['POST'])
def login():
    if request.method=="POST":
     try:
        login_data=request.get_json()
        print("HI")
        userlogin=login_data.get("Login-User")
        passlogin=login_data.get("Login-Password")
        print(userlogin,passlogin)
        cursor.execute("SELECT * FROM users WHERE username=%s AND password=%s",(userlogin,passlogin))
        userils=cursor.fetchall()
        print()
        if(len(userils)>0):
            print(userils[0][0])
            logintok=generate_jwt(userils[0][0],userils[0][1])
            print(logintok)

            return jsonify({"token":logintok,"userils":userils})
        else:
            return jsonify({"message":"No records found"})
     except MySQLdb.Error as e:
        print(e)
        return jsonify({'error': 'Database error', 'details': str(e)}), 500
        
   
if __name__ == '__main__':
    app.run()
