import demistomock as demisto
from CommonServerPython import *


def internal_request(method: str, uri: str, body: Optional[dict] = None) -> dict:
    """A wrapper for demisto.internalHttpRequest.

    Args:
        method (str): HTTP method such as: GET or POST
        uri (str): Server uri to request. For example: "/contentpacks/marketplace/HelloWorld".
        body (dict, optional): Optional body for a POST request. Defaults to {}.

    Returns:
        dict: The body of request response.
    """
    res = demisto.executeCommand(
        f'core-api-{method.lower()}',
        {'uri': uri, 'body': json.dumps(body or {})}
    )
    if is_error(res):
        raise DemistoException(get_error(res))
    return res[0]['Contents']['response']  # type: ignore


def get_instance(instance_name: str) -> dict:
    '''Get the object of the instance with the name provided.

    Args:
        instance_name (str): The name of the instance to get.

    Returns:
        dict: The instance object.
    '''
    integrations = internal_request('post', '/settings/integration/search')
    return next(inst for inst in integrations['instances'] if inst['name'] == instance_name)


def set_instance(instance: dict, parameters: dict) -> dict:
    '''Set an instance configuration with the accounts.

    Args:
        instance (dict): The instance object to configure.
        key (str): The name of the parameter.
        value (Any): The value to set the parameter.

    Returns:
        dict: The server response from the configuration call.
    '''
    for key, value in parameters.items():
        config_parameter: dict = next(param for param in instance['data'] if key in (param['name'], param['display']))
        config_parameter.update({
            'hasvalue': True,
            'value': value
        })
    return internal_request('put', '/settings/integration', instance)


def update_instance(instance_name: str, parameters: dict) -> str:
    '''Update an integration instance with new parameters.

    Args:
        instance_name (str): The name of the instance to configure.
        parameters (dict): The parameters to configure the instance with.

    Returns:
        str: A message regarding the outcome of the script run.
    '''
    try:
        instance = get_instance(instance_name)
        set_instance(instance, parameters)
    except StopIteration as e:
        raise DemistoException(f'Integration instance {instance_name!r} was not found.') from e
    except (TypeError, KeyError) as e:
        raise DemistoException(f'Please make sure a "Core REST API" instance is enabled.\nError: {e}') from e
    return CommandResults(
        readable_output=tableToMarkdown(f'Successfully updated {instance_name!r} with parameters:', parameters)
    )


def main():
    try:
        return_results(update_instance(**demisto.args()))
    except Exception as e:
        return_error(f'Error in SetIntegrationParameters: {e}')


if __name__ in ('__main__', 'builtins', '__builtin__'):
    main()
