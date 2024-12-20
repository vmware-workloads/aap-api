import logging

from aap import Aap, AriaInventory, AriaHosts
from aap.aria_group_mapping import AriaGroupMapping
from aap.aria_groups import AriaGroups

log = logging.getLogger(__name__)


def abx_create(context: object, inputs: dict) -> dict:
    """
        This handler CREATES an inventory on an ansible automation platform server
        and runs a specified job as specified in the inputs.

        Args:
            context: The context object containing information about the ABX event.
            inputs: The inputs provided for the ABX event.
        Returns:
            dict: The outputs generated by the ABX handler.
    """
    log.info(f"Creating resources for project: {inputs.get('__metadata').get('project')}")

    # Connect to server
    with Aap.from_aria(context=context, inputs=inputs) as aap:

        # Find organization
        # Must exist or default will be used if unset
        organization_name = inputs.get('organization_name')
        log.info(f"Organization name: '{organization_name}'")
        aap_organization = aap.search_organizations(name=organization_name)
        if len(aap_organization) == 0:
            msg = f"Could not find organization with name '{organization_name}' on server '{aap.base_url}'"
            log.critical(msg)
            raise ValueError(msg)
        if len(aap_organization) > 1:
            msg = f"Found multiple organization with name '{organization_name}' on server '{aap.base_url}'"
            log.critical(msg)
            raise ValueError(msg)
        aap_organization = aap_organization[0]

        # Find Job Template
        # Must exist, no defaults
        job_template_name = inputs.get('job_template_name')
        log.info(f"Job Template name: '{job_template_name}'")
        aap_job_template = aap.search_job_templates(name=job_template_name)
        if len(aap_job_template) == 0:
            msg = f"Could not find job template with name '{job_template_name}' on server '{aap.base_url}'"
            log.critical(msg)
            raise ValueError(msg)
        if len(aap_job_template) > 1:
            msg = f"Found multiple job template with name '{job_template_name}' on server '{aap.base_url}'"
            log.critical(msg)
            raise ValueError(msg)
        aap_job_template = aap_job_template[0]

        # Find inventory
        # Must NOT exist
        inventory_name = inputs.get('inventory_name')
        log.info(f"Inventory name: '{inventory_name}'")
        aap_inventory = aap.search_inventories(name=inventory_name)
        if len(aap_inventory) > 1:
            err = f"Found multiple inventories with name '{inventory_name}' on server '{aap.base_url}'"
            log.critical(err)
            raise ValueError(err)
        if len(aap_inventory) == 1:
            err = f"Inventory '{inventory_name}' already exists on server '{aap.base_url}'"
            log.critical(err)
            raise ValueError(err)

        # Create inventory
        log.info(f"Creating inventory '{inventory_name}")
        aap_inventory = aap.add_inventory(inventory=AriaInventory.from_aria(inputs=inputs),
                                          organization=aap_organization)

        # Add hosts to inventory
        log.info(f"Adding hosts to inventory")
        aap_hosts = aap.add_hosts(hosts=AriaHosts.from_aria(inputs=inputs),
                                  inventory=aap_inventory)

        # Create groups
        log.info(f"Adding groups to inventory")
        aap_groups = aap.add_groups(groups=AriaGroups.from_aria(inputs=inputs),
                                    inventory=aap_inventory)

        # Add hosts to groups
        log.info(f"Adding hosts to groups")
        aap.add_hosts_to_groups(mapping=AriaGroupMapping.from_aria(inputs=inputs),
                                hosts=aap_hosts,
                                groups=aap_groups)

        # Launch job template
        log.info(f"Launching job template with inventory")
        aap_job = aap.launch_job_template(job_template=aap_job_template, inventory=aap_inventory)

        # Wait for job completion
        log.info(f"Wait for job completion")
        aap_job = aap.wait_on_job(job=aap_job)

        # Print job result
        match aap_job.status.lower():
            case 'successful':
                log.info(aap_job)
            case 'error' | 'failed' | 'cancel' | 'canceled':
                log.error(aap_job)
            case _:
                log.warning(aap_job)

        outputs = {
            "status": aap_job.status.lower(),
            "operation": "create",
            "inventory": {
                "id": aap_inventory.id,
                "url": aap_inventory.url,
                "name": aap_inventory.name,
                "variables": aap_inventory.variables,
            },
            "groups": {
                group.name: {
                    "id": group.id,
                    "url": group.url,
                    "variables": group.variables,
                } for group in aap_groups},
            "hosts": {
                host.name: {
                    "id": host.id,
                    "url": host.url,
                    "variables": host.variables,
                } for host in aap_hosts},
        }

        return outputs
