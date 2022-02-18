# Ansible Collection - ebarrere.aws_workspaces

Inventory plugin for Amazon Workspaces. This was copied from the amazon.aws.aws_ec2 inventory source and updated for the Workspaces API.


    name: az_workspaces
    plugin_type: inventory
    short_description: Amazon Workspaces inventory source
    requirements:
        - amazon.aws
        - boto3
        - botocore
    extends_documentation_fragment:
    - inventory_cache
    - constructed
    - amazon.aws.aws_credentials

    description:
        - Get inventory hosts from Amazon Workspaces.
        - Uses a YAML configuration file that ends with C(az_workspaces.(yml|yaml)).
    notes:
        - If no credentials are provided and the control node has an associated IAM workspace profile then the
          role will be used for authentication.
    author:
        - Elliott Barrere
    options:
        plugin:
            description: Token that ensures this is a source file for the plugin.
            required: True
            choices: ['az_workspaces', 'ebarrere.aws_workspaces.az_workspaces']
        iam_role_arn:
          description: The ARN of the IAM role to assume to perform the inventory lookup. You should still provide AWS
              credentials with enough privilege to perform the AssumeRole action.
        regions:
          description:
              - A list of regions in which to describe Workspaces.
              - If empty (the default) default this will include all regions, except possibly restricted ones like us-gov-west-1 and cn-north-1.
          type: list
          default: []
        filters:
          description:
              - A dictionary of filters.
              - Available filters are listed here U(https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/workspaces.html#WorkSpaces.Client.describe_workspaces).
              - ONLY ONE FILTER is allowed by the API. Order of precedence is directory_id, bundle_id.
          type: dict
          default: {}
        include_extra_api_calls:
          description:
              - Add additional API call for every workspace to include tags.
          type: bool
          default: False
        strict_permissions:
          description:
              - By default if a 403 (Forbidden) error code is encountered this plugin will fail.
              - You can set this option to False in the inventory config file which will allow 403 errors to be gracefully skipped.
          type: bool
          default: True
        use_contrib_script_compatible_sanitization:
          description:
            - By default this plugin is using a general group name sanitization to create safe and usable group names for use in Ansible.
              This option allows you to override that, in efforts to allow migration from the old inventory script and
              matches the sanitization of groups when the script's ``replace_dash_in_groups`` option is set to ``False``.
              To replicate behavior of ``replace_dash_in_groups = True`` with constructed groups,
              you will need to replace hyphens with underscores via the regex_replace filter for those entries.
            - For this to work you should also turn off the TRANSFORM_INVALID_GROUP_CHARS setting,
              otherwise the core engine will just use the standard sanitization on top.
            - This is not the default as such names break certain functionality as not all characters are valid Python identifiers
              which group names end up being used as.
          type: bool
          default: False
        use_contrib_script_compatible_workspaces_tag_keys:
          description:
            - Expose the host tags with workspaces_tag_TAGNAME keys like the old workspaces.py inventory script.
            - The use of this feature is discouraged and we advise to migrate to the new ``tags`` structure.
          type: bool
          default: False