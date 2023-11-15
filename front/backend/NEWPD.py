from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
from functools import wraps
from loguru import logger
import hvac
import requests
import MySQLdb
import jwt
from auth import token_required, validate, generate_jwt
from db import db, cursor
from pdnsreq import pdns_request
from config import user, db_key, SECRET_KEY, api_key
logger.debug(SECRET_KEY)
logger.debug(f"New dub{user}")
logger.debug(api_key)
logger.debug(db_key)
app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})
db = MySQLdb.connect(host='localhost', user=f'{user}', passwd=f'{db_key}', db='powerdns_db')
cursor = db.cursor()
pdns_server = 'http://0.0.0.0:8081'
@app.route('/zones', methods=['GET', 'POST'])
@token_required
def manage_dns_zones(user_id,username):
    if request.method == 'GET':
       
        try:
            cursor.execute('SELECT id, name, master, last_check, type, notified_serial, account, options, catalog   FROM domains')
            zones = cursor.fetchall()
            logger.debug(zones)
            return jsonify(zones)
        except MySQLdb.Error as e:
            logger.error(e)
            return jsonify({'error': 'Database error', 'details': str(e)}), 500
            

    if request.method == 'POST':
       
        try:
            zone_data = request.get_json()
          
            if not all(key in zone_data for key in ('zonena', 'zonemas', 'zonelastcheck', 'zonetype', 'zoneno', 'zoneaccount', 'zoneoptions', 'zonecatalog')):
                return jsonify({'error': 'Missing required fields in zone data'}), 400
        except Exception as e:
            return jsonify({'error': 'Invalid JSON data', 'details': str(e)}), 400

        query = 'INSERT INTO domains (name, master, last_check, type, notified_serial, account, options, catalog,user_id) ' \
                'VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)'
        data = (
            zone_data['zonena'], zone_data['zonemas'], zone_data['zonelastcheck'],
            zone_data['zonetype'], zone_data['zoneno'], zone_data['zoneaccount'],
            zone_data['zoneoptions'], zone_data['zonecatalog'], user_id
        )

        try:
            cursor.execute(query, data)
            db.commit()
            

           
            logger.success("Zone added")
            cursor.execute(f"select id from domains where name=%s",(zone_data['zonena'],))
            ifd=cursor.fetchone()
            cursor.execute("INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled, user_id) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
               (ifd[0], zone_data['zonena'], "SOA", f'ns1.{zone_data["zonena"]}. {username} 0 10800 3600 604800 3600', 3600, 0, 0, user_id))
            db.commit()
            cursor.execute("INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled, user_id) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
               (ifd[0], zone_data['zonena'], "NS", f'ns1.{zone_data["zonena"]}', 3600, 0, 0, user_id))
            db.commit()
            return jsonify({"message": "Zone added"}), 201  
        except MySQLdb.Error as e:
            logger.error(e)
            return jsonify({'error': 'Database error', 'details': str(e)}), 500

@app.route('/zones/<string:zone_name>', methods=['PATCH', 'DELETE'])
@token_required
def manage_dns_zone(user_id,username,zone_name):
    if request.method == 'PATCH':
     cursor.execute('SELECT name FROM domains WHERE name = %s', (zone_name,))
     zone_exists = cursor.fetchone()
     cursor.execute('SELECT user_id from domains where name = %s',(zone_name,))
     su=cursor.fetchone()
     if zone_exists:
        try:
            zone_data = request.get_json()
        except Exception as e:
            logger.error(e)
            return jsonify({'error': 'Invalid JSON data', 'details': str(e)}), 400
        zone_name = zone_data.get('zoneName')
        key = zone_data.get('zoneDetails')
        value = zone_data.get('recorded')
        print(zone_name,key,value)
        
        if(su[0]==user_id):
            try:
                cursor.execute(f"UPDATE domains SET {key}=%s WHERE name = %s",(value,zone_name))
              
                db.commit()
                print(f"Key: {key}, Value: {value}")
                logger.success(f"Zone has been modified")
                return jsonify({"message": f"Zone {zone_name} has been modified"})
            except MySQLdb.Error as e:
                logger.error(e)
                return jsonify({'error': 'Database error', 'details': str(e)}), 500
        else:
                logger.critical("Not authorized to modify data!")
                return jsonify({"message":"Not authorized"})
     else:
        logger.error("Invalid Zone Name")
        return jsonify({"error": "Invalid Zone Name"}), 400

    if request.method == 'DELETE':
            url = f"{pdns_server}/api/v1/servers/localhost/zones/{zone_name}"
            cursor.execute('SELECT id FROM domains WHERE name = %s', (zone_name,))
            result = cursor.fetchone()
            cursor.execute('SELECT user_id from domains where name = %s',(zone_name,))
            s=cursor.fetchone()
            print(s)
            print(result)
    
            if result is None:
                logger.critical("Zone not found")
                return jsonify({'error': 'Zone not found', 'details': f'Zone {zone_name} does not exist.'}), 404

            zone_id = result[0]

            if(s[0]==user_id):
                cursor.execute('DELETE FROM records where domain_id = %s', (zone_id,))
                cursor.execute('DELETE from domains where id=%s',{zone_id})
                db.commit()
    
                logger.success("Records deleted")
                return jsonify({"message": f"Recordsin zone {zone_name} have been deleted and zone has been deleted."})
            else:
                logger.critical("Not authorized to delete")
                return jsonify({'message':'Not authorized to delete'})

@app.route('/zones/<int:zone_id>', methods=['GET', 'POST', 'DELETE', 'PATCH'])
@token_required
def manage(user_id,username,zone_id):
    if request.method == 'GET':
     cursor.execute('SELECT id FROM domains WHERE id = %s', (zone_id,))
     zone_exists = cursor.fetchone()
     if zone_exists:
        try:
            cursor.execute(f'SELECT * FROM records where domain_id ={zone_id}')
            logger.success("Fetched successfully")
            records = cursor.fetchall()
            return jsonify(records)
        
        except MySQLdb.Error as e:
            logger.error(e)
            return jsonify({'error': 'Database error', 'details': str(e)}), 500
     else:
        
        return jsonify({"error": "Invalid Zone ID"}), 400
    elif request.method == 'POST':
     cursor.execute('SELECT id FROM domains WHERE id = %s', (zone_id,))
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

        query = 'INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled,user_id) ' \
                'VALUES (%s, %s, %s, %s, %s, %s, %s, %s)'
        data = (zone_name, zone_master, zone_last_check, zone_type, zone_no, zone_account, zone_options, user_id)

        try:
            print(zone_name)
            cursor.execute(f'SELECT user_id FROM domains WHERE id= {zone_name}')
            us=cursor.fetchone()
            if(us[0]==user_id):
                cursor.execute(query, data)
                db.commit()
                return jsonify({"message": f"Records in zone {zone_id} have been added."})
            else:
                return jsonify({"message": f"NOt authenticated to change this {zone_name}"}) 
        except MySQLdb.Error as e:
            return jsonify({'error': 'Database error', 'details': str(e)}), 400
     else:
        
        return jsonify({"error": "Invalid Zone ID"}), 400

    elif request.method == 'DELETE':
     cursor.execute('SELECT user_id from domains WHERE id=%s',(zone_id,))
     q=cursor.fetchone()
     print(q[0])
     if(q[0]==user_id):
        cursor.execute('SELECT id FROM domains WHERE id = %s', (zone_id,))
        zone_exists = cursor.fetchone()
        if zone_exists:
            try:
            
                cursor.execute(f'DELETE FROM records where domain_id ={zone_id} AND user_id= %s',(user_id,))
                db.commit()
                return jsonify({"message": f"Recordsin zone {zone_id} have been deleted."})
            except MySQLdb.Error as e:
                return jsonify({'error': 'Database error', 'details': str(e)}), 500
        else:
        
            return jsonify({"error": "Invalid Zone ID"}), 400
     else:
         return jsonify({'message':"Not Authenticated"})

    elif request.method == 'PATCH':
     cursor.execute('SELECT id FROM domains WHERE id = %s', (zone_id,))
     zone_exist = cursor.fetchone()
     cursor.execute('SELECT user_id from domains where id = %s',(zone_id,))
     s=cursor.fetchone()
     print(s)
     print(zone_exist)
     if(s[0]==user_id):

        if zone_exist:
            try:
                zone_data = request.get_json()
                record_id = zone_data.get("recId")
                cursor.execute('SELECT id FROM records WHERE id = %s', (record_id,))
                record_exist = cursor.fetchone()
                print(record_exist)
                if record_exist:
                    zone_id = zone_data.get('zoneId')
                    key = zone_data.get('zoneDetails')
                    value = zone_data.get('recorded')
                    query = f"UPDATE records SET {key}=%s WHERE domain_id=%s AND id=%s"
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
     else:
         return jsonify({"message":"NOt auth"})

@app.route('/zones/<int:zone_id>/<string:typer>', methods=['DELETE', 'GET'])
@token_required
def man(user_id,username,zone_id, typer):
    if request.method == 'DELETE':
     cursor.execute('SELECT id FROM domains WHERE id = %s', (zone_id,))
     zone_exists = cursor.fetchone()
     cursor.execute('SELECT user_id from domains where id = %s',(zone_id,))
     sk=cursor.fetchone()
     print(sk)
     print(zone_exists)

     if zone_exists:
         print(typer)
         if(sk[0]==user_id):
            cursor.execute('SELECT type FROM records WHERE type = %s', (typer,))
            record_exist = cursor.fetchone()
            print(record_exist)
            if record_exist:
                try:
                    cursor.execute(f'DELETE FROM records where domain_id =%s AND type = %s', (zone_id,typer))
                    db.commit()
                    return jsonify({"message": f"Records of type '{typer}' in zone {zone_id} have been deleted."})
                except MySQLdb.Error as e:
                    return jsonify({'error': 'Database error', 'details': str(e)}), 400
            else:
                return jsonify({"error": "Invalid Record"}), 400
         else:
             return jsonify({"message":"Not authenticated"})
     else:
        
        return jsonify({"error": "Invalid Zone ID"}), 400

    if request.method == 'GET':
        try:
            cursor.execute(f'SELECT * FROM records where domain_id={zone_id} AND type = %s', (typer,))
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
