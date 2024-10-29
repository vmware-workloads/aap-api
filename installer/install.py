import requests
import yaml
import json
import urllib3
urllib3.disable_warnings()
from datetime import datetime
import time
import sys
import base64


sourceId = "" 
contentSourceId = ""



abxScript = f'aap_api.zip' # Name of the ABX script to 'install'
configFile = f'config.json' # Name of the configuration file



def get_vra_auth_token(token_endpoint, requestData, bearer_endpoint):
    """
        Gets the authentication token from aria.
        First we need the refresh token, we then use this to obtain the full (bearer) token

        Args:
            token_endpoint (str): the url of the token site
            requestData (dict): username & password for auth
            bearer_endpoint (str): the url of the bearer token site

        Returns:
            str: login (bearer) token
    """

    #  Get the initial refresh token
    headers = {"Content-Type": "application/json"}
    body = json.dumps(requestData).encode('utf-8')
    response = requests.post(token_endpoint, 
                             headers=headers, 
                             data=body, 
                             verify=False)

    token_data = response.json()
    access_token = token_data.get("refresh_token")
    requestData = {"refreshToken": access_token}
    body = json.dumps(requestData).encode('utf-8')
  
    # From refresh token get Bearer token
    response = requests.post(bearer_endpoint, 
                             headers=headers, 
                             data=body,
                             verify=False)
    data = response.json()
    bearer_token = data.get("token")
    return bearer_token

def read_config(configFile):
    """
        Reads the configuration file

        Args:
            configFile (str): The name of the config file.

        Returns:
            list: configuration items
    """

    with open(configFile) as config_file:
        config_data = json.load(config_file)
    return config_data

def createOrUpdateAbxAction(projectId,secretIds):
    """
        Creates or updates an ABX action in the specified project.

        Args:
            projectId (str): The ID of the project.
            secretIds (list): A list of secret IDs.

        Returns:
            str: The ID of the created or updated ABX action.
    """

    # Get the list of existing ABX actions
    url = f'{baseUrl}/abx/api/resources/actions'
    resp = requests.get(url, headers=headers, verify=False)
    #print(resp.status_code, resp.text)    
    resp.raise_for_status()
    existing = [x for x in resp.json()["content"] if x["name"] == abxActionName]


    body = {
        "name":abxActionName,
        "metadata":{},
        "runtime": "python",
        "source": open(abxScript).read(),
        "entrypoint":"handler",
        "inputs":{secret:"" for secret in secretIds},
        "cpuShares":1024,
        "memoryInMB":200,
        "timeoutSeconds":900,
        "deploymentTimeoutSeconds":900,
        "dependencies": "requests",        
        "actionType":"SCRIPT",
        "configuration":{},
        "system":False,
        "shared":True,
        "asyncDeployed":False,
        "runtimeVersion": "3.10",        
        "projectId":projectId,
        "scriptSource":0,
        "provider":""
    }
    if len(existing) > 0:
        abxActionId = existing[0]["id"]
        body["id"] = abxActionId
        # If the specified ABX action already exists then update it
        url = f'{baseUrl}/abx/api/resources/actions/{abxActionId}'
        resp = requests.put(url, json=body, headers=headers, verify=False)
        #print(resp.status_code, resp.text)
        resp.raise_for_status()

        return abxActionId
    else:
        # Create a new extensibility action (if it doesn't already exist) to perform the database CRUD operations
        url = f'{baseUrl}/abx/api/resources/actions'
        resp = requests.post(url, json=body, headers=headers, verify=False)
        #print(resp.status_code, resp.text)
        resp.raise_for_status()

        abxActionId = resp.json()["id"]
        return abxActionId



def createOrUpdateAbxActionBundle(projectId,secretIds):
    """
        Creates or updates an ABX action in the specified project.

        Args:
            projectId (str): The ID of the project.
            secretIds (list): A list of secret IDs.

        Returns:
            str: The ID of the created or updated ABX action.
    """


    # Get the list of existing ABX actions
    url = f'{baseUrl}/abx/api/resources/actions'
    resp = requests.get(url, headers=headers, verify=False)
    #print(resp.status_code, resp.text)    
    resp.raise_for_status()
    existing = [x for x in resp.json()["content"] if x["name"] == abxActionName]


    with open(abxScript, "rb") as file:
        encoded_file = base64.b64encode(file.read()).decode("utf-8")




    body = {
        "name":abxActionName,
        "metadata":{},
        "runtime": "python",
        "compressedContent": encoded_file,
        "contentResourceName": abxScript,
        "entrypoint":"aap_api.handler",
        "inputs":{secret:"" for secret in secretIds},
        "cpuShares":1024,
        "memoryInMB":200,
        "timeoutSeconds":900,
        "deploymentTimeoutSeconds":900,
        "dependencies": "requests",        
        "actionType":"SCRIPT",
        "configuration":{},
        "system":False,
        "shared":True,
        "asyncDeployed":False,
        "runtimeVersion": "3.10",        
        "projectId":projectId,
        "scriptSource":0,
        "provider":""
    }
    if len(existing) > 0:
        abxActionId = existing[0]["id"]
        body["id"] = abxActionId
        # If the specified ABX action already exists then update it
        url = f'{baseUrl}/abx/api/resources/actions/{abxActionId}'
        resp = requests.put(url, json=body, headers=headers, verify=False)
        #print(resp.status_code, resp.text)
        resp.raise_for_status()

        return abxActionId
    else:
        # Create a new extensibility action (if it doesn't already exist) to perform the database CRUD operations
        url = f'{baseUrl}/abx/api/resources/actions'
        resp = requests.post(url, json=body, headers=headers, verify=False)
        #print(resp.status_code, resp.text)
        resp.raise_for_status()

        abxActionId = resp.json()["id"]
        return abxActionId


def createOrUpdateAbxBasedCustomResource(projectId, abxActionId, propertySchema):
    """
         Creates or updates the custom resource
         Uses the same ABX for create/read/update/delete - the ABX needs the logic 
         to deal with each.


        Args:
            projectId (str): The ID of the project.
            abxActionId (str): The ID of the ABX action.
            propertySchema (dict): Schema of the Custom Resource. 

        Returns:
            None
    """

    custom_resource_exists = False
    # The extensibility action that this custom resource should be associated with
    abxAction = {
        "id":abxActionId,
        "name":abxActionName,
        "projectId":projectId,
        "type":"abx.action",
    }

    #print(abxAction)

    # create the body of the request 
    body = {
        "displayName":crName,
        "description":"",
        "resourceType":crTypeName,
        "externalType":None,
        "status":"RELEASED",
        "mainActions": {
          "create": abxAction,
          "read":  abxAction,
          "update":  abxAction,
          "delete":  abxAction
        },
        "properties": propertySchema,
        "schemaType": "ABX_USER_DEFINED"
    }


    # Get the list of existing custom resources
    url = f'{baseUrl}/form-service/api/custom/resource-types'
    resp = requests.get(url, headers=headers, verify=False)
    #print(resp.status_code, resp.text)
    #resp.raise_for_status()
    existing = [x for x in resp.json()["content"] if x["displayName"] == crName]
    #print(existing)

    # Create the custom resource if it doesn't already exist
    if len(existing) > 0:
        # Update the custom resource if it already exists
        body["id"] = existing[0]["id"]
        custom_resource_exists = True
    resp = requests.post(url, json=body, headers=headers, verify=False)
    print(body)
    #print(resp.status_code, resp.text)
    resp.raise_for_status()

    # Update the custom resource if it already exists
    if (custom_resource_exists):
        # When tried to re-add the 'additionalActions' to a custom resource, a duplicate key error is raised.
        # Hence, first add the 'mainActions' to a custom resource and only then add any 'additionalActions'
        body["id"] = existing[0]["id"]
        resp = requests.post(url, json=body, headers=headers, verify=False)
        #print(resp.status_code, resp.text)        
        resp.raise_for_status()




def createOrUpdateProject():
    """
        Creates or updates a project in the Aria system.

        Args:
            None

        Returns:
            str: The ID of the created or updated project.
    """

    # Get the list of existing projects
    url = f'{baseUrl}/project-service/api/projects?page=0&size=9999&%24orderby=name%20asc&excludeSupervisor=false'
    resp = requests.get(url, headers=headers, verify=False)
    resp.raise_for_status()
    existing = [x for x in resp.json()["content"] if x["name"] == projectName]

    if len(existing) > 0:
        # If the project 'PROJECT' (This name will change based on the value specified in config.json) already exists then return its id
        return existing[0]["id"]

    # Create a new project called 'PROJECT' (This name will change based on the value specified in config.json) if it doesn't already exist
    body = {
        "name": projectName,
        "description": "",
        "administrators": [],
        "members": [],
        "viewers": [],
        "supervisors": [],
        "constraints": {},
        "properties": {
            "__projectPlacementPolicy": "DEFAULT"
        },
        "operationTimeout": 0,
        "sharedResources": True
    }
    url = f'{baseUrl}/project-service/api/projects'
    resp = requests.post(url, json=body, headers=headers, verify=False)
    #print(resp.status_code, resp.text)
    resp.raise_for_status()
    return resp.json()["id"]



def getSecrets(projectId):
    """
        Retrieves a list of secret IDs based on the given project ID.

        Args:
            projectId (str): The ID of the project.

        Returns:
            list: A list of secret IDs.
    """

    # Retrieve secrets from the platform API
    url = f'{baseUrl}/platform/api/secrets?page=0&size=9999'
    resp = requests.get(url, headers=headers, verify=False)
    #print(resp.status_code, resp.text)
    resp.raise_for_status()
    secretList = resp.json()["content"]

    # Fetch and return the Ids of the secrets
    # credentials like hostname, username, password, certificate check and root CA
    filtered_list = [d for d in secretList if d.get("name") in secrets and d.get("projectId") == projectId]
    if not all(d["name"] in secrets for d in filtered_list):
        raise ValueError(f"Check secrets configuration :{secrets} for project :{projectId}")
    secretIds = [f"psecret:{d['id']}" for d in filtered_list]
    if not secretIds:
        raise ValueError("Unable to create secrets list, check secrets configuration")
    return secretIds


def createSecrets(projectId, inputs):
    """
        Creates or updates secrets in the Aria platform for the given project ID.

        Args:
            projectId (str): The ID of the project.
            inputs (dict): Secrets to add.

        Returns:
            None
    """


    for name,value in inputs.items():
        body = {
                 "name":name,
                 "value":value,
                 "projectId":projectId
        }
        # Get the existing secrets
        url = f'{baseUrl}/platform/api/secrets?$filter=name%20eq%20%27{name}%27'
        resp = requests.get(url, headers=headers, verify=False)
        #print(resp.status_code, resp.text)
        resp.raise_for_status()
        data = resp.json()["content"]
        if len(data) > 0:
            # Update secrets if they already exist
            id = resp.json()["content"][0]["id"]
            url = f'{baseUrl}/platform/api/secrets/{id}'
            resp = requests.patch(url, json=body, headers=headers, verify=False)
            #print(resp.status_code, resp.text)
            resp.raise_for_status()
        else:
            # Create new secrets if they do not already exist
            url = f'{baseUrl}/platform/api/secrets'
            resp = requests.post(url, json=body, headers=headers, verify=False)
            #print(resp.status_code, resp.text)
            resp.raise_for_status()
            

########



# Read the config file
config = read_config(configFile)

# Set the variables from the config file
abxActionName = config["abx_action_name"]  # Name of the ABX action
crName = config["cr_name"]  # Name of the Custom Resource
crTypeName = config["cr_type_name"]  # Name of the Custom Resource Type
baseUrl = config["aria_base_url"]  # Base URL of Aria deployment
projectName = config["project_name"]  # Retrieve the project name from the config


# Get the authentication token from the VCF Automation (vRA) API
token_url = config["aria_base_url"]+"/csp/gateway/am/api/login?access_token=null"
request_data = {"username": config["aria_username"], "password":config["aria_password"]}
bearer_url = config["aria_base_url"]+"/iaas/api/login"

token = get_vra_auth_token(token_url, request_data, bearer_url)  
headers = {
    'authorization': f'Bearer {token}',
    'content-type': 'application/json',
}

# Create or update the project and retrieve its ID
projectId = createOrUpdateProject()


# Create secrets
# These secrets will be used while running/executing the orchestrator action
secrets = {
  "aapURL": config["ansible_url"], 
  "aapUser": config["ansible_user"], 
  "aapPass": config["ansible_password"], 
  "aapRootCA": config["ansible_root_ca"]
}
createSecrets(projectId, secrets)


# Fetch the Ids of the secrets - like hostname, username and password
secretIds = getSecrets(projectId)

# Create/update the ABX action 
#abxActionId = createOrUpdateAbxAction(projectId,secretIds)
abxActionId = createOrUpdateAbxActionBundle(projectId,secretIds)


# Create/update the custom resource
properties = {
  "properties": {
    "hosts": {"type": "object","title": "Hosts","description": "Array of hosts to add to the AAP inventory"},
    "verbose": {"type": "boolean","title": "Verbose Messages","description": "Enable verbose messages for debugging","default": False},
    "aapURL": {"type": "string","title": "Ansible Server URL","description": "URL of the Ansible Automation Platform REST API","default": ""},
    "aapSSL": {"type": "boolean","title": "Ansible Server URL","description": "Verify SSL Connection to the Ansible Server","default": "False"},      
    "host_groups": {"type": "object","title": "Ansible inventory host groups","description": "(optional) Dictionary with groups as key and list of hosts in that group.","default": {}},
    "host_variables": {"type": "object","title": "Ansible inventory host variables","description": "(optional) Any host variables to pass on to AAP","default": {}},
    "inventory_name": {"type": "string","title": "Ansible inventory name","description": "The name of the inventory to be created on Ansible Automation Platform"},
    "group_variables": {"type": "object","title": "AAP Group Variables","description": "(optional) Any group variables to pass on to AAP","default": {}},
    "job_template_name": {"type": "string","title": "Ansible template name","description": "Name of the template to run on Ansible Automation Platform"},
    "organization_name": {"type": "string","title": "Organization Name","description": "(optional) The name of the org to pass on to AAP","default": ""},
    "inventory_variables": {"type": "object","title": "Ansible inventory variables","description": "(optional)  Dictionary with inventory variables","default": {}}
  },
    "required": ["hosts","inventory_name","job_template_name"]
}      
createOrUpdateAbxBasedCustomResource(projectId, abxActionId, properties)





