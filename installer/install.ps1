
$abxScript = 'aap_api.zip' # Name of the ABX script to 'install'
$configFile = 'config.json' # Name of the configuration file


# Load required assembly for forms
Add-Type -AssemblyName System.Windows.Forms

function Create-Form {
    param(
        [PSCustomObject]$config,
        [string]$title
    )

    
    $configNames = $config.psobject.properties.name
    $configValues = $config.psobject.properties.value   
    
    
    # Get the largest strings from the input. This will determine the sizes of the gui elements
    
    $mylargeststring = $configValues | Sort length -desc | Select -first 1
    $mylargestname = $configNames | Sort length -desc | Select -first 1
    
    
    # Specify a font to obtain sizes deterministically 
    $Font = New-Object System.Drawing.Font('Arial', 10)
    
    
    # Compute the sizes of the largest strings
    
    $largestStringSize = [System.Windows.Forms.TextRenderer]::MeasureText($mylargeststring, $Font)
    $largestNameSize = [System.Windows.Forms.TextRenderer]::MeasureText($mylargestname, $Font)
    
    
    # Positions & constants
    
    $spacing = 30
    $xBorder = 130
    $yBorder = 100
    $yPos = 10  # this will be incremented
    $xPos = 10
    $labelWidth = $largestNameSize.width+50
    $boxWidth = $largestStringSize.width
    $boxXlocation=$largestNameSize.width+100
    $submitButtonText = "Submit"
    $cancelButtonText = "Cancel"
    
    
    # Create a form
    
    $form = New-Object System.Windows.Forms.Form
    $form.Text = $title
    $form.Width = $largestNameSize.width+$largestStringSize.width+$xBorder
    $form.Height = $yBorder + ($spacing * $configNames.Count)
    $form.Font = $Font
    

    # Create a hash table to hold the textboxes for each field
    $textBoxes = @{}


    # Create labels and text boxes dynamically based on keys
    foreach ($key in $configNames) {
        # Create a label for each key
        $label = New-Object System.Windows.Forms.Label
        $label.Text = "$key"
        $label.Width = $labelWidth
        $label.Location = New-Object System.Drawing.Point($xPos, $yPos)
        $form.Controls.Add($label)

        # Create a text box for each value
        $textBox = New-Object System.Windows.Forms.TextBox
        $textBox.Width = $boxWidth
        $textBox.Location = New-Object System.Drawing.Point($boxXlocation, $yPos)
        # Handle null values
        $textBox.Text = if ($config.$key -eq $null) { "" } else { $config.$key }
        $form.Controls.Add($textBox)

        # Store the textBox reference in the hash table
        $textBoxes[$key] = $textBox

        # Increment position for next set of controls
        $yPos += $spacing
    }

    # Create a button to submit
    $button = New-Object System.Windows.Forms.Button
    $button.Text = $submitButtonText
    $button.DialogResult = [System.Windows.Forms.DialogResult]::OK
    $button.Location = New-Object System.Drawing.Point($xPos, $yPos)
    $form.AcceptButton = $button
    $form.Controls.Add($button)
    
    $CancelButton = New-Object System.Windows.Forms.Button
    $CancelButton.Text = $cancelButtonText
    $CancelButton.Location = New-Object System.Drawing.Point(($xPos+$xBorder), $yPos)
    $CancelButton.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
    $form.CancelButton = $CancelButton
    $form.Controls.Add($CancelButton)

    

    # Show the form and capture the result
    $result = $form.ShowDialog()
    
    $data = @{}

    if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
        write-host "Submit pressed"
        #$data = @{}
        foreach ($key in $textBoxes.Keys) {
            $data[$key] = $textBoxes[$key].Text
        }
    }
    else {
        
        $data   = $config
    }
    
    $buttonData = @{
                    result = $result
                    data   = $data
    }   
    
    #write-host "result is:" $buttonData.result
    #write-host "data is:" $buttonData.data     
    return $buttonData
    

    
    #write-host $result
    
}           

function Get-VraAuthToken {
    param(
        [string]$TokenEndpoint,       # URL of the token site
        [hashtable]$RequestData,      # Username & Password for auth (as a hashtable)
        [string]$BearerEndpoint       # URL of the bearer token site
    )


    # Convert request data to JSON
    $jsonBody = $RequestData | ConvertTo-Json

    # Headers for the request
    $headers = @{"Content-Type" = "application/json"}

    # Disable SSL verification (equivalent to verify=False in Python)
    add-type @"
    using System.Net;
    using System.Security.Cryptography.X509Certificates;
    public class TrustAllCertsPolicy : ICertificatePolicy {
        public bool CheckValidationResult(
            ServicePoint srvPoint, X509Certificate certificate,
            WebRequest request, int certificateProblem) {
                return true;
        }
    }
"@
    [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy

    # Step 1: Get the initial refresh token
    try {
        $response = Invoke-RestMethod -Uri $TokenEndpoint -Method Post -Headers $headers -Body $jsonBody -ErrorAction Stop
        $refreshToken = $response.refresh_token

        if (-not $refreshToken) {
            throw "Refresh token not found in the response."
        }
    } catch {
        Write-Error "Error getting refresh token: $_"
        return
    }



    # Step 2: Use the refresh token to get the bearer token
    $bearerRequestData = @{ refreshToken = $refreshToken } | ConvertTo-Json
    

    try {
        $bearerResponse = Invoke-RestMethod -Uri $BearerEndpoint -Method Post -Headers $headers -Body $bearerRequestData -ErrorAction Stop
        $bearerToken = $bearerResponse.token

        if (-not $bearerToken) {
            throw "Bearer token not found in the response."
        }
        


        return $bearerToken
    } catch {
        Write-Error "Error getting bearer token: $_"
        return
    }
}

function CreateOrUpdateProject {
    param (
        [string]$BaseUrl,          # Base URL for the Aria system
        [string]$ProjectName,      # Name of the project (from config)
        [hashtable]$Headers        # Headers for the request, including authorization
    )

    # Step 1: Get the list of existing projects
    $url = "$BaseUrl/project-service/api/projects?page=0&size=20&%24orderby=name%20asc&excludeSupervisor=false"
    
    
    try {
        $response = Invoke-RestMethod -Uri $url -Method Get -Headers $Headers -ErrorAction Stop 
    
        foreach ($project in $response.content) {
            if ($project.name -eq $ProjectName) {
                $foundProject = $project
                break
            }
        }
        
        if ($foundProject) {
            write-host "Exsiting project ID: $($foundProject.id)"
            return $foundProject.id
        }
        else {
            write-host "Will create a new project: '$ProjectName'"
        }

    } catch {
        Write-Error "Error retrieving project list: $_"
        return
    }

    # Step 2: Create a new project if it doesn't exist
    $body = @{
        name           = $ProjectName
        description    = ""
        administrators = @()
        members        = @()
        viewers        = @()
        supervisors    = @()
        constraints    = @{}
        properties     = @{
        "__projectPlacementPolicy" = "DEFAULT"
        }
        operationTimeout = 0
        sharedResources  = $true
    } | ConvertTo-Json

    $createUrl = "$BaseUrl/project-service/api/projects"
    
    try {
        $createResponse = Invoke-RestMethod -Uri $createUrl -Method Post -Headers $Headers -Body $body -ContentType "application/json" -ErrorAction Stop
        return $createResponse.id
    } catch {
        Write-Error "Error creating project: $_"
        return
    }
}

function Create-OrUpdateAbxAction {
    param (
        [string]$projectId,  # The ID of the project
        [array]$secretIds,   # List of secret IDs
        [string]$abxActionName,
        [string]$abxScript,
        [string]$baseUrl,
        [hashtable]$headers  # The headers (e.g., authorization)
    )

    # Get the list of existing ABX actions
    $url = "$baseUrl/abx/api/resources/actions"
    $response = Invoke-RestMethod -Uri $url -Headers $headers -Method Get 

    $existing = $response.content | Where-Object { $_.name -eq $abxActionName }
    
    $myScriptSource = Get-Content -Raw -Path $abxScript | out-string

    # Prepare the body for the request
    $body = @{
        name                    = $abxActionName
        metadata                = @{}
        runtime                 = "python"
        source                  = $myScriptSource 
        entrypoint              = "handler"
        inputs                  = $secretIds
        cpuShares               = 1024
        memoryInMB              = 200
        timeoutSeconds          = 900
        deploymentTimeoutSeconds = 900
        dependencies            = "requests"
        actionType              = "SCRIPT"
        configuration           = @{}
        system                  = $false
        shared                  = $true
        asyncDeployed           = $false
        runtimeVersion          = "3.10"
        projectId               = $projectId
        scriptSource            = 0
        provider                = ""
    }
    
    $jsonBody = $body | ConvertTo-Json -Depth 100
    #write-host $existing

    # If the action exists, update it
    if ($existing) {
        $abxActionId = $existing[0].id
        $body.id = $abxActionId
        $url = "$baseUrl/abx/api/resources/actions/$abxActionId"
        $response = Invoke-RestMethod -Uri $url -Headers $headers -Method Put -Body $jsonBody 
    }
    else {
        # Create a new ABX action if it doesn't exist
        $url = "$baseUrl/abx/api/resources/actions"
        $response = Invoke-RestMethod -Uri $url -Headers $headers -Method Post -Body $jsonBody 
        $abxActionId = $response.id
    }

    return $abxActionId
}

function Create-OrUpdateAbxActionBundle {
    param (
        [string]$projectId,  # The ID of the project
        [hashtable]$secretIds,   # List of secret IDs
        [string]$abxActionName,
        [string]$abxScript,
        [string]$baseUrl,
        [hashtable]$headers  # The headers (e.g., authorization)
    )

    # Get the list of existing ABX actions
    $url = "$baseUrl/abx/api/resources/actions"
    $response = Invoke-RestMethod -Uri $url -Headers $headers -Method Get 
    $existing = $response.content | Where-Object { $_.name -eq $abxActionName }
    
    
    $abxScriptLocation = Join-path -path $PWD -ChildPath aap_api.zip 

    # Read the file and encode it in base64
    $encoded_file = [Convert]::ToBase64String([System.IO.File]::ReadAllBytes($abxScriptLocation))

    # Prepare the body for the request
    $body = @{
        name                    = $abxActionName
        metadata                = @{}
        runtime                 = "python"
        compressedContent       = $encoded_file
        contentResourceName     = $abxScript
        source                  = $myScriptSource 
        entrypoint              = "aap_api.handler"
        inputs                  = $secretIds
        cpuShares               = 1024
        memoryInMB              = 200
        timeoutSeconds          = 900
        deploymentTimeoutSeconds = 900
        dependencies            = "requests"
        actionType              = "SCRIPT"
        configuration           = @{}
        system                  = $false
        shared                  = $true
        asyncDeployed           = $false
        runtimeVersion          = "3.10"
        projectId               = $projectId
        scriptSource            = 0
        provider                = ""
    }
    
    $jsonBody = $body | ConvertTo-Json -Depth 100
    #write-host $existing

    # If the action exists, update it
    if ($existing) {
        $abxActionId = $existing[0].id
        $body.id = $abxActionId
        $url = "$baseUrl/abx/api/resources/actions/$abxActionId"
        $response = Invoke-RestMethod -Uri $url -Headers $headers -Method Put -Body $jsonBody 
    }
    else {
        # Create a new ABX action if it doesn't exist
        $url = "$baseUrl/abx/api/resources/actions"
        $response = Invoke-RestMethod -Uri $url -Headers $headers -Method Post -Body $jsonBody 
        $abxActionId = $response.id
    }

    return $abxActionId
}


function Create-OrUpdateAbxBasedCustomResource {
    param (
        [string]$projectId,
        [string]$abxActionId,
        [hashtable]$propertySchema,
        [string]$crName,
        [string]$crTypeName,
        [string]$abxActionName,
        [string]$baseUrl,
        [hashtable]$headers
    )

    $custom_resource_exists = $false

    # The ABX action object
    $abxAction = @{
        id        = $abxActionId
        name      = $abxActionName
        projectId = $projectId
        type      = "abx.action"
    }

    # Create the body of the request
    $body = @{
        displayName = $crName
        description = ""
        resourceType = $crTypeName
        externalType = $null
        status = "RELEASED"
        mainActions = @{
            create = $abxAction
            read = $abxAction
            update = $abxAction
            delete = $abxAction
        }
        properties = $propertySchema
        schemaType = "ABX_USER_DEFINED"
    }

    # Get the list of existing custom resources
    $url = "$baseUrl/form-service/api/custom/resource-types"
    $response = Invoke-RestMethod -Uri $url -Headers $headers -Method Get 
    $existing = $response.content | Where-Object { $_.displayName -eq $crName }

    # Create or update the custom resource
    if ($existing) {
        # Update the custom resource if it exists
        $body.id = $existing[0].id
        $custom_resource_exists = $true
    }

    $jsonBody = $body | ConvertTo-Json -Depth 100
    #write-host $jsonBody

    # Send the POST request to create or update
    $response = Invoke-RestMethod -Uri $url -Headers $headers -Method Post -Body $jsonBody

    if ($custom_resource_exists) {
        # Add additional actions if needed after the main actions are added
        $body.id = $existing[0].id
        $response = Invoke-RestMethod -Uri $url -Headers $headers -Method Post -Body $jsonBody
    }
}


function Get-Secrets {
    param (
        [string]$projectId,  # The ID of the project
        [string]$baseUrl,    # Base URL for the API
        [hashtable]$headers  # The headers (e.g., authorization)
    )

    # List of expected secret names
    #$secrets = @('aapURL', 'aapUser', 'aapPass', 'aapSSL', 'aapRootCA')

    # Retrieve secrets from the platform API
    $url = "$baseUrl/platform/api/secrets?page=0&size=9999"
    $response = Invoke-RestMethod -Uri $url -Headers $headers -Method Get 

    # Assuming the response is a JSON object containing "content" with an array of secrets
    $secretList = $response.content



    # Filter the secrets based on name and projectId
    $filteredSecrets = @()
    foreach ($secret in $secretList) {
        if ($secret.name -in $secrets -and $secret.projectId -eq $projectId) {
            $filteredSecrets += $secret
        }
        #write-host $secret.name
        
    }

    # Validate that all expected secrets are present
    $missingSecrets = $secrets | Where-Object { $_ -notin $filteredSecrets.name }
    if ($missingSecrets) {
        throw "Check secrets configuration: $secrets for project: $projectId"
    }

    # Extract and return the secret IDs in the desired format
    # Here we create a hash table with the secret as the key
    # And the value as null (this is what the VCF Auto abx api expects)
    $secretIds = @{}
    foreach ($secret in $filteredSecrets) {
        $secretIds.add("psecret:$($secret.id)","")
    }

    # If no secret IDs were found, raise an error
    if (-not $secretIds) {
        throw "Unable to create secrets list, check secrets configuration."
    }

    return $secretIds
}


function Create-Secrets {
    param (
        [string]$projectId,          # The ID of the project
        [hashtable]$inputs,          # Secrets to add (key-value pairs)
        [string]$baseUrl,            # Base URL for the API
        [hashtable]$headers          # Headers (e.g., Authorization)
    )


    
    # Loop through each secret in the inputs hashtable
    foreach ($name in $inputs.Keys) {
        $value = $inputs[$name]
        
        
        # Prepare the body for the request
        $body = @{
            name      = $name
            value     = $value
            projectId = $projectId
        }
        
        
        # Get the existing secret (filtered by name)
        $url = "$baseUrl/platform/api/secrets?`$filter=name eq '$name'"
        $response = Invoke-RestMethod -Uri $url -Headers $headers -Method Get 
        
        $jsonBody = $body | ConvertTo-Json -Depth 100
        $jsonBody
        
        # Check if the secret already exists
        $existingSecrets = $response.content
        if ($existingSecrets.projectId -eq $projectId) {
            
            # Update the existing secret
            write-host "updating existing secrets"
            $id = $existingSecrets[0].id
            $url = "$baseUrl/platform/api/secrets/$id"
            #$url
            $response = Invoke-RestMethod -Uri $url -Headers $headers -Method Patch -Body $jsonBody 
            $response | out-null  # Optionally suppress output

        }
        else {
            # Create a new secret if it doesn't exist
            write-host "creating new secrets"
            $url = "$baseUrl/platform/api/secrets"
            $response = Invoke-RestMethod -Uri $url -Headers $headers -Method Post -Body $jsonBody 
            $response | Out-Null  # Optionally suppress output
        }
    }
}

##########




# Initialize the pre-populated text values as an empty hash table
$prePopulatedData = @{}

# Check if the JSON file exists
if (Test-Path $configFile) {
    # Read the existing JSON file
    $config = Get-Content -Path $configFile -Raw | ConvertFrom-Json

    $config
    
    # Populate prePopulatedData with the fields from the JSON
    #$prePopulatedData = ($config.psobject.properties) | ForEach-Object -Process {$_.Name}

    # Display the form & capture the result
    $myForm = Create-Form -config $config -title "AAP API Installer"
    
    if ($myForm.result -eq "OK") {
        "Form submitted"
        
        # Convert to JSON and write to file
        $json = $myForm.data | ConvertTo-Json
        $json | Out-File -FilePath $configFile
            
        $json
    }
    else {
        "Cancelled"
        exit
    }
}
else {
    write-host "Can't find the config file" $configFile
}

# re-read the config file to capture any changes
$config = Get-Content -Path $configFile -Raw | ConvertFrom-Json


# Set the variables from the config file
$abxActionName = $config.abx_action_name  # Name of the ABX action
$crName = $config.cr_name  # Name of the Custom Resource
$crTypeName = $config.cr_type_name  # Name of the Custom Resource Type
$baseUrl = $config.aria_base_url  # Base URL of Aria deployment
$projectName = $config.project_name  # Retrieve the project name from the config


$token_url = $config.aria_base_url+"/csp/gateway/am/api/login?access_token=null"
$request_data = @{username=$config.aria_username; password=$config.aria_password}
$bearer_url = $config.aria_base_url+"/iaas/api/login"


$token = Get-VraAuthToken -TokenEndpoint $token_url -RequestData $request_data -BearerEndpoint $bearer_url
$headers = @{authorization='Bearer '+$token; 'content-type'='application/json'}




# Create or update the project and retrieve its ID
$projectId = createOrUpdateProject -BaseUrl $config.aria_base_url -ProjectName $projectName -Headers $headers


# Create secrets
# These secrets will be used while running/executing the orchestrator action
$secrets = @{
  aapURL = $config.ansible_url; 
  aapUser = $config.ansible_user; 
  aapPass = $config.ansible_password; 
  aapRootCA = $config.ansible_root_ca
}
Create-Secrets -projectID $projectId -inputs $secrets -baseUrl $config.aria_base_url -headers $headers


# Fetch the Ids of the secrets 
$secretIds = Get-Secrets -projectID $projectId -baseUrl $config.aria_base_url -headers $headers


$abxActionParams = @{ 'projectID' = $projectId;
                      'secretIds' = $secretIds;
                      'abxActionName' = $abxActionName;
                      'abxScript' = $abxScript;
                      'baseUrl' = $config.aria_base_url;
                      'headers' = $headers 
                    }
                      

# Create/update the ABX action 
#$abxActionId = Create-OrUpdateAbxAction @abxActionParams
$abxActionId = Create-OrUpdateAbxActionBundle @abxActionParams


# Create/update the custom resource
$properties = @{
    properties = @{
        hosts              = @{ type = "object"; title = "Hosts"; description = "Array of hosts to add to the AAP inventory" }
        verbose            = @{ type = "boolean"; title = "Verbose Messages"; description = "Enable verbose messages for debugging"; default = $false }
        aapURL             = @{ type = "string"; title = "Ansible Server URL"; description = "URL of the Ansible Automation Platform REST API"; default = "" }
        aapSSL             = @{ type = "boolean"; title = "Ansible Server Verify SSL Conneciton"; description = "Verify SSL Connection to the Ansible Server"; default = "False" }
        host_groups        = @{ type = "object"; title = "Ansible inventory host groups"; description = "(optional) Dictionary with groups as key and list of hosts in that group."; default = @{} }
        host_variables     = @{ type = "object"; title = "Ansible inventory host variables"; description = "(optional) Any host variables to pass on to AAP"; default = @{} }
        inventory_name     = @{ type = "string"; title = "Ansible inventory name"; description = "The name of the inventory to be created on Ansible Automation Platform" }
        group_variables    = @{ type = "object"; title = "AAP Group Variables"; description = "(optional) Any group variables to pass on to AAP"; default = @{} }
        job_template_name  = @{ type = "string"; title = "Ansible template name"; description = "Name of the template to run on Ansible Automation Platform" }
        organization_name  = @{ type = "string"; title = "Organization Name"; description = "(optional) The name of the org to pass on to AAP"; default = "" }
        inventory_variables = @{ type = "object"; title = "Ansible inventory variables"; description = "(optional) Dictionary with inventory variables"; default = @{} }
    }
    required = @("hosts", "inventory_name", "job_template_name")
}

$customResourceParams = @{ 'projectID' = $projectId;
                           'abxActionId' = $abxActionId;
                           'propertySchema' = $properties;
                           'crName' = $crName;
                           'crTypeName' = $crTypeName;
                           'abxActionName' = $abxActionName;
                           'baseUrl' = $config.aria_base_url;
                           'headers' = $headers
                          }
                    

Create-OrUpdateAbxBasedCustomResource @customResourceParams
