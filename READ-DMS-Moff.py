import uuid
import json
import requests
import time
import os
import traceback
import urllib3
urllib3.disable_warnings()


def handler(context, inputs):
     
    ######## General Variables #####################

    baseUrl = context.getSecret(inputs["dms-baseUrl"])
    userName = context.getSecret(inputs["dms-userName"])
    password = context.getSecret(inputs["dms-password"])
    id = inputs["id"]

    # Collect JWT Token
    print('Collecting JWT Token...')   
    body = {
        "email": userName,
        "password": password
    }
    response_getJWT = requests.post('https://' + baseUrl + '/provider/session', data=json.dumps(body), verify=False)
    #print(response_getJWT)
    #print(response_getJWT.headers)

    if response_getJWT.status_code == 200:
        myJWT_data = response_getJWT.json()
        orgId = response_getJWT.json()['orgMemberships'][0]['orgId']
        dmsaccessToken = response_getJWT.headers['Authorization']
    else:
        print('Collecting JWT Token failed:')
        print(response_getJWT.status_code)


    # Reading DB
    print('Reading DB...') 
    headers = {"Accept":"application/vnd.vmware.dms-v1+json","X-Org-ID":orgId, "Authorization":dmsaccessToken }
    response_getDB = requests.get('https://' + baseUrl + '/provider/databases/' + id, headers=headers, verify=False)
    #print(response_getDB)

    if response_getDB.status_code == 200:
        myDB_Properties = response_getDB.json()
        print('Read Complete')
        instanceName = response_getDB.json()['instanceName']
        version = response_getDB.json()['version']
        dbType = response_getDB.json()['dbType']
        role = response_getDB.json()['role']
        primaryFqdn = response_getDB.json()['primaryFqdn']
        ip = response_getDB.json()['ip']
        dbMgmtIp = response_getDB.json()['dbMgmtIp']
        status = response_getDB.json()['status']
        #print(myDB_Properties)
    else:
        print('Reading DB failed:')
        print(response_getDB.status_code)

    outputs = {
        "dbUUID": id,
        "instanceName": instanceName,
        "version": version,
        "dbType": dbType,
        "role": role,
        "primaryFqdn": primaryFqdn,
        "ip": ip,
        "dbMgmtIp": dbMgmtIp,
        "status": status,
        "id": id
    }

    return outputs    





