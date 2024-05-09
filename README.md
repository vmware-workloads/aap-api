# AAP-API
VMware Aria Automation action to implement custom resources to interface with Ansible Automation Platform. These actions and custom resources implement a more complete interface. 

- Create inventories with more than one host
- Create groups and add hosts to 0 or more groups
- Create inventory variables
- Create group variables
- Create host variables
- Invoke a job with an inventory
- Wait and poll on the job status

## Installation

Note: These instructions are based and tested on Aria Automation 8.16. 

### Actions

1. In Aria Automation Assembler, open **Extensibility**, then select **Actions**.

   <img src="./assets/images/aap_api_install_01.png" alt="Aria Extensibility Actions" width="400"/>
</br>
</br>

2. Select **New**, and fill out the following fields:
   * Name: aap_api
   * Project: ***\<select the project for the action\>***

   <img src="./assets/images/aap_api_install_02.png" alt="New Action" width="400"/>
</br>
</br>

3. In the new action:
   * Select **Python 3.10**
   * Select **Write Script**
   * Copy and paste the aap_api.py code in the code section.

   <img src="./assets/images/aap_api_install_03.png" alt="New Action Parameters 1" width="400"/>
</br>
</br>

4. In the new action:
   * Set the main function to **handler** 
   * In the **Dependancy** enter the following:
     * ***requests***
   * Leave the **FaaS provider** as ***Auto Select*** 

   <img src="./assets/images/aap_api_install_04.png" alt="New Action Parameters 2" width="400"/>
</br>
</br>   

5. Repeat steps 1 to 4 for the following actions. 
   * ***aap_api.py***
   * ***aap_read.py***
   * ***aap_delete.py***
   
   <img src="./assets/images/aap_api_install_05.png" alt="AAP Actions" width="400"/>
</br>
</br>

### Custom Resources

6. In Aria Automation Assembler, open **Design**, then select **Custom Resources**. 

   <img src="./assets/images/aap_api_install_06.png" alt="Aria Custom Resources" width="400"/>
</br>
</br>

7. Select **New**, and enter the following:
   * Name: ***Ansible Automation Platform*** 
   * Resource Type: ***custom.api.ansible_automation_platform***
   * Activate: ***enabled***
   * Scope: ***\<as required\>***
   * Based on: ***ABX user defined schema***
   
   <img src="./assets/images/aap_api_install_07.png" alt="New Custom Resource" width="400"/>
</br>
</br>

8. Scroll down to the **Lifecycle Actions** and select the ABX actions previously created, then click **Create**.
   * Create: ***aap_api***
   * Read: ***aad_read***
   * Destroy: ***aap_delete***
   
   <img src="./assets/images/aap_api_install_08.png" alt="Lifecyle Actions" width="400"/>
</br>
</br>

9.  The **Custom Resources** lists the newly created resource.
   
    <img src="./assets/images/aap_api_install_09.png" alt="AAP Customer Resource" width="400"/>
</br>
</br>

## Usage


