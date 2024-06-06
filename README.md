# AAP-API
VMware Aria Automation action to implement custom resources to interface with Ansible Automation Platform. These actions and custom resources implement a more complete interface. 

- Create inventories with more than one host
- Create groups and add hosts to 0 or more groups
- Create inventory variables
- Create group variables
- Create host variables
- Invoke a job with an inventory
- Wait and poll on the job status

## Deployment
This section outlines the steps to deploy and configure the Ansible Automation Platform API in Aria Automation Assembler. These steps are based and tested on Aria Automation 8.16. 

### Action Constants

We start by adding the Ansible Automation Platform URL and credentials that will be used by the actions. 

1. Under  **Extensibility**, then **Actions Constants**.
   <br>
   <br>
   <img src="./assets/images/action_constants.png" alt="AAP Actions" width="400"/>


2. Add the following parameters:
   * ***username***: user defined in Ansible Automation Platform
   * ***password***: password for the user
   * ***base_url***: url of the Ansible Automation Platform server

   
### Actions

#### Using Source Code
For the simplest installation, follow the instructions below. 

It is also possible to clone the repository and add sync via the 'integration > github' facility in the infrastructure section of aria automation (see [Using Automation Assembler](https://docs.vmware.com/en/VMware-Aria-Automation/SaaS/Using-Automation-Assembler/GUID-86778362-8C3B-4276-9F83-33E320EC960E.html)). 

1. In Aria Automation Assembler, open **Extensibility**, then select **Actions**.
   <br>
   <br>
   <img src="./assets/images/aap_api_install_01.png" alt="Aria Extensibility Actions" width="400"/>


2. Select **New**, and fill out the following fields:
   <br>
   <br>
   <img src="./assets/images/aap_api_install_02.png" alt="New Action" width="400"/>
   * Name: aap_api
   * Project: ***\<select the project for the action\>***


3. In the new action:
   <br>
   <br>
   <img src="./assets/images/aap_api_install_03.png" alt="New Action Parameters 1" width="400"/>
   * Select **Python 3.10**
   * Select **Write Script**
   * Copy and paste the aap_api.py code in the code section.


4. In the new action:
   <br>
   <br>
   <img src="./assets/images/aap_api_install_04.png" alt="New Action Parameters 2" width="400"/>
   * Set the main function to **handler** 
   * In the **Dependancy** enter the following:
     * ***requests***
   * Leave the **FaaS provider** as ***Auto Select***
   

5. Repeat steps 1 to 4 for the following actions. 
   <br>
   <br>
   <img src="./assets/images/aap_api_install_05.png" alt="AAP Actions" width="400"/>
   * ***aap_api.py***
   * ***aap_read.py***
   * ***aap_delete.py***


#### Using Zip Bundles
In this approach the script and all dependencies are bundled in a zip file. This method greatly simplifies the distribution of the actions and provides a solution to air-gaped environments where Aria Automation would not be able to download dependancies (e.g. 'requests').  

**Note**. The zip bundles are provided as downloads on the projects releases. The bundles can also be created manually using the following procedure:

[Create a ZIP package for Python runtime extensibility actions](https://docs.vmware.com/en/VMware-Aria-Automation/8.16/Using-Automation-Assembler/GUID-CC6DEEF1-49E8-4881-82A6-FA10DC0135E8.html)

1. Download the required zip bundles:
   <br>
   <br>
   <img src="./assets/images/aap_api_install_zip_01.png" alt="Download Zip bundles" width="400"/>
   * aap_api.zip
   * aap_read.zip
   * aap_delete.zip


2. In Aria Automation Assembler, select **Extensibility**, **Library**, then **Actions**. Select **New**.
   <br>
   <br>
   <img src="./assets/images/aap_api_install_zip_02.png" alt="Download Zip bundles" width="400"/>


3. At the ***New Action*** window, enter the following information, then click **Next**.
   <br>
   <br>
   <img src="./assets/images/aap_api_install_zip_03.png" alt="Download Zip bundles" width="400"/>
   * Name: ***aap_api***
   * Project: ***\<select the appropriate project\>***
   * Share with all projects in the organization: ***\<enable as required\>***

   
4. In the action properties, select the drop-down, then select ***Import Package***.
   <br>
   <br>
   <img src="./assets/images/aap_api_install_zip_04.png" alt="Download Zip bundles" width="400"/>


5. Click the ***Select File*** button, then choose the appropriate zip bundle.
   <br>
   <br>
   <img src="./assets/images/aap_api_install_zip_05.png" alt="Download Zip bundles" width="400"/>
   * aap_api → aap_api.zip
   * aap_read → aap_read.zip
   * aap_delete → aap_delete.zip

5. At the action properties, enter the following information, then click **Save** and **Close**.<br>
   <br>
   **Note**: The action constants are the variables created in the previous section. 
   <br>
   <br>
   <img src="./assets/images/aap_api_install_zip_06.png" alt="Download Zip bundles" width="400"/>
   * Main function :
     * aap_api → aap_api.handler
     * aap_read → aap_read.handler
     * aap_delete → aap_delete.handler
   * FaaS provider: Auto Select
   * Default inputs:
     * Action Constant: base_url
     * Action Constant: username
     * Action Constant: password


### Custom Resources

1. In Aria Automation Assembler, open **Design**, then select **Custom Resources**. 
   <br>
   <br>
   <img src="./assets/images/aap_api_install_06.png" alt="Aria Custom Resources" width="400"/>


2. Select **New**, and enter the following:
   <br>
   <br>
   <img src="./assets/images/aap_api_install_07.png" alt="New Custom Resource" width="400"/>
   * Name: ***Ansible Automation Platform*** 
   * Resource Type: ***custom.api.ansible_automation_platform***
   * Activate: ***enabled***
   * Scope: ***\<as required\>***
   * Based on: ***ABX user defined schema*** 
   

3. Scroll down to the **Lifecycle Actions** and select the ABX actions previously created, then click **Create**.
   <br>
   <br>
   <img src="./assets/images/aap_api_install_08.png" alt="Lifecyle Actions" width="400"/>
   * Create: ***aap_api***
   * Read: ***aad_read***
   * Destroy: ***aap_delete***


4. Select the **Properties** tab and create the following properties.
   <br>
   <br>
   <img src="./assets/images/aap_api_install_08b.png" alt="AAP Customer Resource" width="400"/>
```yaml
properties:
  hosts:
    type: object
  verbose:
    type: boolean
    default: false
  host_groups:
    type: object
  host_variables:
    type: object
    default: {}
  inventory_name:
    type: string
    encrypted: false
  group_variables:
    type: object
    default: {}
  job_template_name:
    type: string
  organization_name:
    type: string
    default: Default
  inventory_variables:
    type: object
    default: {}
```

5. The **Custom Resources** lists the newly created resource.
   <br>
   <br>
   <img src="./assets/images/aap_api_install_09.png" alt="AAP Customer Resource" width="400"/>

   
## Usage
This section describes the AAP_API custom resource variables, and how to use them.

```yaml
resources:
  Custom_api_ansible_automation_platform_1:
    type: Custom.api.ansible_automation_platform
    properties:
      verbose: true
      organization_name: Default
      job_template_name: CRDB Template
      inventory_name: ${env.deploymentId}
      inventory_variables:
        use_ssl: true
        lb_address:
          - ${resource.web_lb.address}
      hosts:
        - ${resource.vm-1.*}
        - ${resource.vm-2.*}
        - ${resource.vm-3.*}
      group_variables:
        group1:
          sql_port: 26257
          rpc_port: 26357
        group2:
           service_name: cockroachdb
      host_variables:
        crdb-vm:
          rack: 1
          verbose: true
      host_groups:
        group1:
          - ${resource.vm-1.*}
        group2:
          - ${resource.vm-2.*}
        group3:
          - ${resource.vm-1.*}
          - ${resource.vm-2.*}
```
<br>
<br>

### Variables 

#### organization_name
* Description: The name of the Ansible Automation Platform organization.
* Type: String
* Required: No
* Default: Default 
<br>
<br>
<img src="./assets/images/aap_api_variables_organization_name.png" alt="AAP Customer Resource" width="400"/>
<br>
<br>

#### job_template_name
* Description: The name of the Ansible Automation Platform organization.
* Type: String
* Required: **Yes**
<br>
<br>
<img src="./assets/images/aap_api_variables_job_template_name.png" alt="AAP Customer Resource" width="400"/>
<br>
<br>

#### inventory_name
* Description: Name that will be used to create the inventory on the Ansible Automation Platform server. This value must be unique in the Ansible Automation Platform inventories. 
* Type: String
* Required: **Yes**

To ensure the name is unique, it is suggested to use Aria Automation environment variables, such as ***deploymentId***.
```yaml
# this will create an inventory with the Aria Deployment UUID
inventory_name: ${env.deploymentId}

# this deployment ID can be prefixed or suffixed with other variables or strings
inventory_name: kafka-${env.deploymentId}
inventory_name: ${env.orgId}-${env.deploymentId}
inventory_name: ${env.deploymentId}-${env.requestedBy}
```
<br>
<img src="./assets/images/aap_api_variables_inventory_name.png" alt="AAP Customer Resource" width="400"/>
<br>
<br>

#### inventory_variables
* Description: This variables accepts a mapping with any valid yaml datatypes, including mappings. The variables defined here will be added as inventory variables.
* Type: Mapping
* Required: No
<br>
<br>

```yaml
inventory_variables:
   use_ssl: true            # boolean
   name: prod1              # string
   lb_address:              # list
     - 192.168.1.1
     - 192.168.1.2
   port: 80                 # numeric
   credentials:             # mapping
      user: joe
      password: qwerty      # string
```
<br>
<img src="./assets/images/aap_api_variables_inventory_variables.png" alt="AAP Customer Resource" width="400"/>
<br>
<br>

#### hosts
* Description: This variables contains the inventory hosts.
* Type: List of Cloud.vSphere.Machine
* Required: **Yes**

This variable expects a list of Aria Automation resources of type ***Cloud.vSphere.Machine***.
```yaml
hosts:
  - ${resource.control-center.*}
  - ${resource.zookeeper.*}
  - ${resource.kafka-broker.*}
```
<br>
<img src="./assets/images/aap_api_variables_hosts.png" alt="AAP Customer Resource" width="400"/>
<br>
<br>

#### host_variables
* Description: This variables expects a mapping of variables that will be assigned to the host(s). The mapping uses the ***Cloud.vSphere.Machine*** name to select the host(s).
* Type: Mapping
* Required: No

**Note**: When creating multiple ***Cloud.vSphere.Machine*** resources using the Aria Automation Assembler **count** variable, the host variables are applied to all the machines. If hosts require different variable or values, then multiple ***Cloud.vSphere.Machine*** instances (i.e. count: 1) with unique names will need to be created, and variables assigned to each one.
```yaml
resources:
  crdb-vm:           # the resource name
    type: Cloud.vSphere.Machine
 #
 # [...]   
 #
  aap_api:
    host_variables:
      crdb-vm:
        rack: 1
        port: 80
        verbose: true
        disks: ${input.diskConfig}
```
<br>
<img src="./assets/images/aap_api_variables_host_variables.png" alt="AAP Customer Resource" width="400"/>
<br>
<br>


#### host_groups
* Description: This variables defines the groups, and which hosts are part of the group.
* Type: Mapping of list of Cloud.vSphere.Machine
* Required: No
<br>
<br>

```yaml
host_groups:
  control_center:
    - ${resource.control-center.*}
  zookeeper:
    - ${resource.zookeeper.*}
  kafka_broker:
    - ${resource.kafka-broker.*}
```
<br>
<img src="./assets/images/aap_api_variables_host_groups_01.png" alt="AAP Customer Resource" width="400"/>
<br>
<img src="./assets/images/aap_api_variables_host_groups_02.png" alt="AAP Customer Resource" width="400"/>
<br>
<br>

####  group_variables
* Description: 
* Type: Mapping 
* Required: No

The name of the group must match a group defined in ***host groups***. 
```yaml
group_variables:
  crdb:
    psql_port: 26257
    rpc_port: 26357
```
<br>
<img src="./assets/images/aap_api_variables_group_variables.png" alt="AAP Customer Resource" width="400"/>
<br>
<br>
