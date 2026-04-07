from bluecat_adapter.bluecat_exception import BluecatAdapterException
from ipaddress import IPv4Address
from re import findall, compile

## USEFUL HELPERS like options, mac_address validations, FQDN validations, etc.


def log_location(func_name: str):
    """
    Generate a string that shows the function within this file that generated the log.
    :param func_name: The function name to add to the log location string.
    :return: The formatted log location string.
    """
    return f"{__name__}=>{func_name} :"


def check_options(options: str, endpoint: str):
    option_store = {}
    sub_options = options.split("|")
    for sub_option in sub_options:
        if "=" not in sub_option:
            raise BluecatAdapterException(
                f"Sub-option does not contain an equals sign: {sub_option}"
            )
        sub_option_split = sub_option.split("=")
        option_store[sub_option_split[0]] = sub_option_split[1]

    keys = option_store.keys()
    match endpoint:
        case "getIP4NetworksByHint" | "getZonesByHint":
            for key in keys:
                if key not in ["hint", "overrideType", "accessRight"]:
                    raise BluecatAdapterException(
                        f"Unexpected key {key} in suboption for endpoint: {endpoint}"
                    )
            pass
        case "getAliasesByHint" | "getHostRecordsByHint":
            for key in keys:
                if key not in ["hint", "retrieveFields"]:
                    raise BluecatAdapterException(
                        f"Unexpected key {key} in suboption for endpoint: {endpoint}"
                    )
        case _:
            raise BluecatAdapterException(f"Invalid endpoint: {endpoint}")


def check_mac_address(mac_address: str):
    """Checks validity of MAC addresses. If valid, no exception is thrown."""
    mac_address = mac_address.replace("-", "")
    mac_address = mac_address.replace(":", "")
    if len(mac_address) != 12:
        raise BluecatAdapterException(f"Invalid MAC address: {mac_address}")


def check_ip_address(ip_address: str):
    try:
        IPv4Address(ip_address)
    except ValueError:
        raise BluecatAdapterException(f"Invalid IP address: {ip_address}")


def check_fqdn(fqdn: str):
    pattern = compile(
        r"(?=^.{4,253}$)(^((?!-)[a-zA-Z0-9-]{1,63}(?<!-)\.)+[a-zA-Z]{2,63}$)"
    )
    matches = findall(pattern, fqdn)
    if len(matches) == 0:
        raise BluecatAdapterException(f"The FQDN is invalid: {fqdn}")
