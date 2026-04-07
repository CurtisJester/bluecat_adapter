from bluecat_adapter.bluecat_adapter_helper import (
    log_location,
    check_options,
    check_mac_address,
    check_ip_address,
    check_fqdn,
)
from rest_adapter.rest_adapter import RestAdapter, BluecatAdapterException
from util.consts import load_dotenv, DOTENV_PATH, getenv
from bluecat_adapter.bluecat_consts import *
from bluecat_adapter.models import Result

from logging import ERROR, DEBUG, Logger
from ipaddress import IPv4Network, IPv4Address
from re import search


class BluecatAdapter(RestAdapter):
    """
    Bluecat Adapter Class - Provides API methods for the Bluecat Proteus REST API.
    No necessary arguments, optional are the filename and log level.
    Uses ENV file for user and pass to auth and store BAM Auth Token.
    BLUECAT_REST is the constant for the hostname. Defined in Consts file.
    """

    def __init__(
        self,
        filename: str = "bluecat_adapter.log",
        log_level: str = "DEBUG",
        logger: Logger = None,
        ssl_verify: bool = True,
    ):
        super().__init__(
            hostname=BLUECAT_REST,
            api_key="",
            ver="v1",
            ssl_verify=ssl_verify,
            filename=filename,
            suffix="",
            log_level="DEBUG",
        )
        load_dotenv(DOTENV_PATH)
        self._authenticate()
        self.parameters = {}

    def _authenticate(self) -> None:
        """
        Authenticate with the username and password from the .env file. Returns a token; stored in the session headers.
        """
        log_loc = log_location("_authenticate")
        response = self._do_logless(
            http_method="GET",
            endpoint="login",
            ep_params={"username": getenv("API_USER"), "password": getenv("API_PASS")},
        )
        if not response.ok:
            raise BluecatAdapterException(f"Authentication failed: {response.text}")
        token = search(r"BAMAuthToken: (.*) <-", response.text)
        if not token:
            raise BluecatAdapterException(f"Authentication failed: {response.text}")
        self.log(level="INFO", msg=f"{log_loc} Auth Success")
        self._api_key = token.group(1)
        self.session.headers.update(
            {
                "Authorization": f"BAMAuthToken: {self._api_key}",
            }
        )

    def is_authenticated(self) -> bool:
        """
        :return: True if authenticated (API key != None), False otherwise.
        """
        return self._api_key is not None

    def add_params(self, params: dict) -> None:
        """
        Add parameters to the current set of parameters held.
        :param params: A dictionary of parameters to add.
        """
        if not self.parameters:
            raise BluecatAdapterException(
                "There must be at least one parameter set before using add_params."
            )
        self.parameters.update(params)

    def set_params(self, params: dict) -> None:
        """
        Clear current parameters and update the parameters with the dictionary given.
        :param params: KV Dict for parameters.
        """
        self.parameters.clear()
        self.parameters.update(params)

    def format_error_raise_exception(
        self, log_loc: str, result: Result, exc_msg: str
    ) -> None:
        """
        Log an error message and throw an exception.
        :param log_loc: The location of the calling function.
        :param result: The result that contains the error.
        :param exc_msg: The message to pass to the exception.
        """
        self.log(level="ERROR", msg=result.add_error_message(log_loc=log_loc))
        if not exc_msg:
            exc_msg = result.def_err_msg
        raise BluecatAdapterException(exc_msg)

    # DELETE Endpoints
    def delete_object(self, object_id: int) -> Result:
        """
        Generic delete endpoint for deleting objects.
        :param object_id: The ID of the object to delete.
        :return: The Result object containing the response of the delete request.
        """
        log_loc = log_location("delete_object")
        self.set_params({"objectId": object_id})
        result = self.delete(endpoint=DELETE_MAIN, ep_params=self.parameters)
        if not result.is_ok():
            self.format_error_raise_exception(
                log_loc=log_loc,
                result=result,
                exc_msg=f"Delete {object_id} failed. Status code: {result.status_code}",
            )
        return result

    def delete_access_right(self, entity_id: int, user_id: int) -> Result:
        """
        Deletes an access right for a specified entity user combination.
        # todo: Test user and entity in test infosec zone; are both params needed?
        :param entity_id: The entity to which the access right is applied.
        :param user_id: The user to whom this access right is applied.
        :return: The Result object containing the response of the specific delete request.
        """
        log_loc = log_location("delete_access_right")
        self.set_params({"entityId": entity_id, "userId": user_id})
        result = self.delete(endpoint=DELETE_ACCESS_RIGHT, ep_params=self.parameters)
        if not result.is_ok():
            self.format_error_raise_exception(
                log_loc=log_loc,
                result=result,
                exc_msg=f"Delete access right for user: {user_id} and entity: {entity_id} failed. Status code: {result.status_code}",
            )
        return result

    def delete_device_instance(self, config_name: str, identifier: str) -> Result:
        """Deletes either the IP address or MAC address (and all related DNS entries including host records,
        PTR records, or DHCP reserved addresses) on both the Address Manager and DNS/DHCP Server based on
        the IPv4 address or a MAC address supplied.
        Todo: figure this config name arg out
        :param config_name: Name of parent configuration.
        :param identifier: The IP address or MAC address to query."""
        log_loc = log_location("delete_device_instance")
        self.set_params(
            {"configName": config_name, "identifier": identifier, "options": ""}
        )
        result = self.delete(endpoint="/", ep_params=self.parameters)
        if not result.is_ok():
            self.format_error_raise_exception(
                log_loc=log_loc,
                result=result,
                exc_msg=f"Delete device: {identifier} failed. Status code: {result.status_code}",
            )
        return result

    # GET Endpoints
    def get_ip4_address(self, ip_address: str) -> Result:
        """
        Return the result containing the response from searching for this IP string.
        :param ip_address: Search for this IPv4 address.
        :return: Result object from request.
        """
        log_loc = log_location("get_ip4_address")
        check_ip_address(ip_address=ip_address)

        self.set_params({"address": ip_address, "containerId": IPAM_PARENT_ID})
        result = self.get(endpoint=GET_IPV4, ep_params=self.parameters)
        if not result.is_ok():
            self.format_error_raise_exception(
                log_loc=log_loc,
                result=result,
                exc_msg=f"Get IPV4 Address {ip_address} failed. Status code: {result.status_code}",
            )
        return result

    def get_parent(self, entity_id: int) -> Result:
        """
        Get the parent object for the entity provided.
        :param entity_id: The ID of the entity on which to seek a parent.
        :return: The Result object containing the parent.
        """
        log_loc = log_location("get_parent")
        self.set_params({"entityId": entity_id})
        result = self.get(endpoint=GET_PARENT, ep_params=self.parameters)
        if not result.is_ok():
            self.format_error_raise_exception(
                log_loc=log_loc,
                result=result,
                exc_msg=f"Get Parent for {entity_id} failed. Status code: {result.status_code}",
            )
        return result

    def get_entity_by_id(self, entity_id: int) -> Result:
        log_loc = log_location("get_entity_by_id")
        self.set_params({"id": entity_id})
        result = self.get(endpoint=GET_ENTITY_BY_ID, ep_params=self.parameters)
        if not result.is_ok():
            self.format_error_raise_exception(
                log_loc=log_loc,
                result=result,
                exc_msg=f"Get Entity by ID {entity_id} failed. Status code: {result.status_code}",
            )
        return result

    def get_entity_by_name(self, entity_name: str, obj_type: str) -> Result:
        """
        # todo: ensure the given ParentID is truly what we need and we *dont* need to allow to be passed in.
        Get the entity by name and object type, parent ID is given by the IPAM parent ID
        :param entity_name: The name of the entity.
        :param obj_type: The object type of the entity.
        :return: The Result object containing the entity.
        """
        if obj_type not in OBJ_TYPES:
            raise BluecatAdapterException(OBJ_MISMATCH.format(obj_type=obj_type))
        log_loc = log_location("get_entity_by_name")
        self.set_params(
            {
                "count": MAX_OBJ_RETURN_COUNT,
                "name": entity_name,
                "parentId": IPAM_PARENT_ID,
                "start": START_INDEX,
                "type": obj_type,
            }
        )
        result = self.get(endpoint=GET_ENTITY_BY_NAME, ep_params=self.parameters)
        if not result.is_ok():
            self.format_error_raise_exception(
                log_loc=log_loc,
                result=result,
                exc_msg=f"Get Entity by name {entity_name} failed. Status code: {result.status_code}",
            )
        return result

    def get_entities(self, obj_type: str, parent_id: int):
        log_loc = log_location("get_entities")
        self.set_params(
            {
                "count": MAX_COUNT,
                "parentId": parent_id,
                "start": START_INDEX,
                "type": obj_type,
            }
        )

        result = self.get(endpoint=GET_ENTITIES, ep_params=self.parameters)
        if not result.is_ok():
            self.format_error_raise_exception(
                log_loc=log_loc,
                result=result,
                exc_msg=f"Get Entities failed. Status code: {result.status_code}",
            )
        return result

    def get_linked(
        self, obj_type: str, entity_id: int = None, parent_id: int = None
    ) -> Result:
        """
        This will return linked entites of obj_type by either parent or an entity id.
        :param obj_type: The object type of the entities to return.
        :param entity_id: The entity to search for linked entities of type obj_type.
        :param parent_id: The parent entity under which to return entities of type obj_type.
        :return: The Result object containing the linked entities of type obj_type.
        """
        log_loc = log_location("get_linked")
        if not entity_id and not parent_id:
            raise BluecatAdapterException(
                "You need to provide either entity_id or parent_id."
            )
        if entity_id and parent_id:
            raise BluecatAdapterException(
                "You must provide one of these two, not both: entity_id or parent_id."
            )
        if entity_id is not None:
            self.set_params({"entityId": entity_id})
        if parent_id is not None:
            self.set_params({"parentId": parent_id})
        self.add_params(
            {"count": MAX_OBJ_RETURN_COUNT, "start": START_INDEX, "type": obj_type}
        )

        endpoint = GET_LINKED_ENTITIES
        result = self.get(endpoint=endpoint, ep_params=self.parameters)
        if not result.is_ok():
            self.format_error_raise_exception(
                log_loc=log_loc,
                result=result,
                exc_msg=f"Get entities endpoint: {endpoint} failed. Status code: {result.status_code}",
            )
        return result

    def get_entities_by_name_using_options(
        self,
        obj_type: str,
        parent_id: int,
        entity_name: str = None,
        ignore_case: bool = True,
    ) -> Result:
        """
        Return the entities matching the type, parent, and entity name provided.
        :param entity_name: The name on which to search.
        :param obj_type: The object type on which to return matched named entities.
        :param parent_id: The parent entity under which to return entities of type obj_type.
        :param ignore_case: Ignore case on entity name.
        :return: The Result object containing the array of matched named entities.
        """
        log_loc = log_location("get_entities_by_name_using_options")
        self.set_params(
            {
                "count": MAX_OBJ_RETURN_COUNT,
                "parentId": parent_id,
                "start": START_INDEX,
                "type": obj_type,
            }
        )

        if entity_name:
            self.add_params(
                {
                    "name": entity_name,
                    "options": f"ignoreCase={ignore_case}",
                }
            )
        result = self.get(endpoint=GET_ENTITIES_BY_NAME, ep_params=self.parameters)
        if not result.is_ok():
            self.format_error_raise_exception(
                log_loc=log_loc,
                result=result,
                exc_msg=f"Get Entities by Name {entity_name} failed. Status code: {result.status_code}",
            )
        return result

    def get_access(self, user_id: int = None, entity_id: int = None) -> Result:
        """
        This will return the access rights for a user.
        :param user_id: The user ID on which to get access rights.
        :param entity_id: The entity ID on which to get access rights.
        :return: The Result object containing the array of access rights.
        """
        log_loc = log_location("get_access_for_user")
        if not user_id and not entity_id:
            raise BluecatAdapterException(
                "You must provide either user_id or entity_id."
            )
        if user_id and entity_id:
            raise BluecatAdapterException(
                "You must provide one of these two, not both: user_id or entity_id."
            )

        self.set_params(
            {
                "count": MAX_OBJ_RETURN_COUNT,
                "start": START_INDEX,
            }
        )

        if user_id:
            self.add_params({"userId": user_id})
        if entity_id:
            self.add_params({"entityId": entity_id})

        result = self.get(endpoint=GET_LINKED_ENTITIES, ep_params=self.parameters)
        if not result.is_ok():
            self.format_error_raise_exception(
                log_loc=log_loc,
                result=result,
                exc_msg=f"Get access for user {user_id} failed. Status code: {result.status_code}",
            )
        return result

    def get_zones_by_hint(self, options: list[str], container_id: int = None) -> Result:
        log_loc = log_location("get_zones_by_hint")
        self.set_params(
            {
                "count": MAX_OBJ_RETURN_COUNT,
                "containerId": container_id if container_id else IPAM_PARENT_ID,
                "start": START_INDEX,
                # 'options': options
                # todo: is this even worth keeping in, not sure that the options will ever be used
            }
        )

    def bam_health(self) -> Result:
        log_loc = log_location("bam_health")
        self.set_params({"Content-Type": "application/json"})
        # odd url for this endpoint
        result = self.session.get(
            url=f"{BLUECAT_REST}/{BAMHEALTH}", params=self.parameters
        )
        if not result.is_ok():
            self.format_error_raise_exception(
                log_loc=log_loc,
                result=result,
                exc_msg=f"Get bam_health failed. Status code: {result.status_code}",
            )
        return result

    def custom_search(self, filters: list[str], obj_type: str) -> Result:
        log_loc = log_location("custom_search")
        custom_types = [
            "IP4Block",
            "IP4Network",
            "IP4Addr",
            "GenericRecord",
            "HostRecord",
        ]
        if obj_type not in custom_types:
            raise BluecatAdapterException(
                f"Custom search needs the necessary obj_type in set: {custom_types}"
                f" -- obj_type supplied: {obj_type}"
            )
        self.set_params(
            {
                "count": MAX_COUNT,
                "filters": filters,
                "options": [],
                "start": START_INDEX,
                "type": obj_type,
            }
        )
        result = self.get(endpoint=CUSTOM_SEARCH, ep_params=self.parameters)
        if not result.is_ok():
            self.format_error_raise_exception(
                log_loc=log_loc,
                result=result,
                exc_msg=f"Custom search failed. Status code: {result.status_code}",
            )
        return result

    def get_by_hint(
        self, options: str, alias: bool = True, records: bool = False
    ) -> Result:
        """
        Defaults to looking for alias records.
        :param options:
        :param endpoint: One of (aliases) getAliasesByHint or (records) getRecordsByHint
        :return:
        """
        endpoint = (
            GET_ALIASES_BY_HINT if alias and not records else GET_HOST_RECORDS_BY_HINT
        )

        log_loc = log_location(f"get_by_hint_{endpoint}")
        check_options(options, endpoint)
        exc_msg_identifier = f"{endpoint.lower()}"
        self.set_params(
            {"count": MAX_OBJ_RETURN_COUNT, "options": options, "start": START_INDEX}
        )
        result = self.get(endpoint=endpoint, ep_params=self.parameters)
        if not result.is_ok():
            self.format_error_raise_exception(
                log_loc=log_loc,
                result=result,
                exc_msg=f"Action: {exc_msg_identifier} failed. "
                f"Options supplied: {options}. "
                f"Status code: {result.status_code}",
            )
        return result

    # Left in for the understanding of why we consolidated these functions, but if design needs to revert, here they are.
    # def get_aliases_by_hint(self, options: str = "") -> Result:
    #     log_loc = log_location("get_aliases_by_hint")
    #     check_options(options)
    #     self.set_params({
    #         'count': MAX_OBJ_RETURN_COUNT,
    #         'options': options,
    #         'start': START_INDEX
    #     })
    #      result = self.get(endpoint=endpoint, ep_params=self.parameters)
    #      if not result.is_ok():
    #           self.format_error_raise_exception(
    #           log_loc=log_loc, result=result,
    #           exc_msg=f" Get Aliases by Hint failed. Options supplied: {options}. Status code: {result.status_code}"
    #            )
    #       return result

    # def get_host_records_by_hint(self, options: str = "") -> Result:
    #     log_loc = log_location("get_host_records_by_hint")
    #     check_options(options)
    #     self.set_params({
    #         'count': MAX_OBJ_RETURN_COUNT,
    #         'options': options,
    #         'start': START_INDEX
    #     })
    #     result = self.get(endpoint=GET_HOST_RECORDS_BY_HINT, ep_params=self.parameters)
    #     if not result.is_ok():
    #         self.format_error_raise_exception(
    #             log_loc=log_loc, result=result,
    #             exc_msg=f"Get records by hint: {options} failed. Status code: {result.status_code}"
    #         )
    #     return result

    def get_configuration_groups(self) -> Result:
        log_loc = log_location("get_configuration_groups")
        result = self.get(endpoint=GET_CONFIGURATION_GROUPS, ep_params=self.parameters)
        if not result.is_ok():
            self.format_error_raise_exception(
                log_loc=log_loc,
                result=result,
                exc_msg=f"Get configuration groups failed. Status code: {result.status_code}",
            )
        return result

    def get_configuration_setting(self, configuration_id: int) -> Result:
        log_loc = log_location("get_configuration_setting")
        self.set_params({"configurationId": configuration_id, "settingName": ""})
        result = self.get(endpoint=GET_CONFIGURATION_SETTING, ep_params=self.parameters)
        if not result.is_ok():
            self.format_error_raise_exception(
                log_loc=log_loc,
                result=result,
                exc_msg=f"Get Configuration Setting for configuration: {configuration_id} failed. Status code: {result.status_code}",
            )
        return result

    def get_configurations_by_group(self, group_name: str) -> Result:
        log_loc = log_location("get_configurations_by_group")
        self.set_params({"groupName": group_name, "properties": ""})
        result = self.get(
            endpoint=GET_CONFIGURATIONS_BY_GROUP, ep_params=self.parameters
        )
        if not result.is_ok():
            self.format_error_raise_exception(
                log_loc=log_loc,
                result=result,
                exc_msg=f"Get configuration group {group_name} failed. Status code: {result.status_code}",
            )
        return result

    # def get_entities_by_name_using_options(self, name: str, obj_type: str, parent_id: int = IPAM_PARENT_ID) -> Result:
    #     log_loc = log_location("get_entities_by_name_using_options")
    #     if obj_type not in OBJ_TYPES:
    #         raise BluecatAdapterException(f"Supplied obj_type {obj_type} not a valid object type.")
    #     self.set_params({
    #         'count': MAX_OBJ_RETURN_COUNT,
    #         'name': name,
    #         'options': 'ignoreCase=false',
    #         'parentId': parent_id,
    #         'type': obj_type
    #     })
    #     result = self.get(endpoint=GET_ENTITIES_BY_NAME_USING_OPTIONS, ep_params=self.parameters)
    #     if not result.is_ok():
    #         self.format_error_raise_exception(
    #             log_loc=log_loc, result=result,
    #             exc_msg=f"Get entities by name: {name} using options failed. Status code: {result.status_code}"
    #         )
    #     return result

    def get_entity_by_cidr(
        self, cidr: str, obj_type: str, parent_id: int = IPAM_PARENT_ID
    ) -> Result:
        log_loc = log_location("get_entity_by_cidr")
        if obj_type not in NET_OBJ_TYPES:
            raise BluecatAdapterException(
                f"Supplied obj_type {obj_type} not a valid network object type: {NET_OBJ_TYPES}."
            )
        try:
            IPv4Network(cidr)
        except ValueError as e:
            raise BluecatAdapterException(f"Invalid cidr {cidr}: {e}")
        self.set_params({"cidr": cidr, "parentId": parent_id, "type": obj_type})
        result = self.get(endpoint=GET_ENTITY_BY_CIDR, ep_params=self.parameters)
        if not result.is_ok():
            self.format_error_raise_exception(
                log_loc=log_loc,
                result=result,
                exc_msg=f"Get entity by CIDR {cidr} failed. Status code: {result.status_code}",
            )
        return result

    def get_entity_by_prefix(
        self, prefix: str, obj_type: str, container_id: int = IPAM_PARENT_ID
    ) -> Result:
        log_loc = log_location("get_entity_by_prefix")
        if obj_type not in NET_OBJ_TYPES:
            raise BluecatAdapterException(
                f"Supplied obj_type: {obj_type} not a valid network object type: {NET_OBJ_TYPES}."
            )
        self.set_params(
            {"containerId": container_id, "prefix": prefix, "type": obj_type}
        )
        result = self.get(endpoint=GET_ENTITY_BY_PREFIX, ep_params=self.parameters)
        if not result.is_ok():
            self.format_error_raise_exception(
                log_loc=log_loc,
                result=result,
                exc_msg=f"Get entity by prefix {prefix} failed. Status code: {result.status_code}",
            )
        return result

    def get_entity_by_range(
        self, addr_start: str, addr_end: str, parent_id: int = IPAM_PARENT_ID
    ) -> Result:
        """Returns an IPv4 DHCP range object by calling it using its range."""
        log_loc = log_location("get_entity_by_range")
        try:
            st = IPv4Address(addr_start)
            end = IPv4Address(addr_end)
            assert st < end
        except ValueError as e:
            raise BluecatAdapterException(
                f"Invalid address on either: {addr_start} or {addr_end}: {e}"
            )
        self.set_params(
            {
                "address1": addr_start,
                "address2": addr_end,
                "parentId": parent_id,
                "type": "DHCP4Range",
            }
        )
        result = self.get(endpoint=GET_ENTITY_BY_RANGE, ep_params=self.parameters)
        if not result.is_ok():
            self.format_error_raise_exception(
                log_loc=log_loc,
                result=result,
                exc_msg=f"Get entity by range [{addr_start} -> {addr_end}] failed. Status code: {result.status_code}",
            )
        return result

    def get_ip4_networks_by_hint(
        self, options: str, container_id: int = IPAM_PARENT_ID
    ) -> Result:
        log_loc = log_location("get_ip4_networks_by_hint")
        check_options(options)
        self.set_params(
            {
                "containerId": container_id,
                "count": MAX_OBJ_RETURN_COUNT,
                "options": options,
                "start": START_INDEX,
            }
        )
        result = self.get(endpoint=GET_IP4_NETWORKS_BY_HINT, ep_params=self.parameters)
        if not result.is_ok():
            self.format_error_raise_exception(
                log_loc=log_loc,
                result=result,
                exc_msg=f"Get IP4 Networks by hint {options} failed. Status code: {result.status_code}",
            )
        return result

    def get_ip_ranged_by_ip(
        self,
        address: str,
        obj_type: str = "IP4Block",
        container_id: int = IPAM_PARENT_ID,
    ) -> Result:
        log_loc = log_location("get_ip_ranged_by_ip")
        if obj_type not in NET_RANGE_TYPES:
            raise BluecatAdapterException(
                f"Object type of {obj_type} is not supported. Choose one of: {NET_RANGE_TYPES}"
            )
        self.set_params(
            {"address": address, "containerId": container_id, "type": obj_type}
        )
        result = self.get(endpoint=GET_IP_RANGED_BY_IP, ep_params=self.parameters)
        if not result.is_ok():
            self.format_error_raise_exception(
                log_loc=log_loc,
                result=result,
                exc_msg=f"Get IP Range by IP failed for {address} with parent type: {obj_type}. Status code: {result.status_code}",
            )
        return result

    def get_mac_address(
        self, mac_address: str, configuration_id: str = IPAM_PARENT_ID
    ) -> Result:
        log_loc = log_location("get_mac_address")
        check_mac_address(mac_address=mac_address)
        self.set_params(
            {
                "configurationId": configuration_id,
                "macAddress": mac_address,
            }
        )
        result = self.get(endpoint=GET_MAC_ADDRESS, ep_params=self.parameters)
        if not result.is_ok():
            self.format_error_raise_exception(
                log_loc=log_loc,
                result=result,
                exc_msg=f"Get MAC Address of {mac_address} failed. Status code: {result.status_code}",
            )
        return result

    def get_network_linked_properties(self, network_id: int) -> Result:
        log_loc = log_location("get_network_linked_properties")
        self.set_params({"networkId": network_id})
        result = self.get(
            endpoint=GET_NETWORK_LINKED_PROPERTIES, ep_params=self.parameters
        )
        if not result.is_ok():
            self.format_error_raise_exception(
                log_loc=log_loc,
                result=result,
                exc_msg=f"Get network (networkId: {network_id} linked properties failed. Status code: {result.status_code}",
            )
        return result

    def get_next_available_ip4_address(self, parent_id: int) -> Result:
        log_loc = log_location("get_next_available_ip4_address")
        self.set_params({"parentId": parent_id})
        result = self.get(
            endpoint=GET_NEXT_AVAILABLE_IP4_ADDRESS, ep_params=self.parameters
        )
        if not result.is_ok():
            self.format_error_raise_exception(
                log_loc=log_loc,
                result=result,
                exc_msg=f"Get next available IP4Address in parent object: {parent_id} failed. Status code: {result.status_code}",
            )
        return result

    def get_user_defined_fields(
        self, obj_type: str, only_required: bool = False
    ) -> Result:
        log_loc = log_location("get_user_defined_fields")
        if obj_type not in OBJ_TYPES:
            raise BluecatAdapterException(f"Invalid object type: {obj_type}")
        self.set_params({"requiredFieldsOnly": only_required, "type": obj_type})
        result = self.get(endpoint=GET_USER_DEFINED_FIELDS, ep_params=self.parameters)
        if not result.is_ok():
            self.format_error_raise_exception(
                log_loc=log_loc,
                result=result,
                exc_msg=f"Get user defined fields failed. Status code: {result.status_code}",
            )
        return result

    def get_zones_by_hint(
        self, options: str, container_id: int = IPAM_PARENT_ID
    ) -> Result:
        log_loc = log_location("get_zones_by_hint")
        check_options(options=options, endpoint=GET_ZONES_BY_HINT)
        self.set_params(
            {
                "containerId": container_id,
                "count": MAX_OBJ_RETURN_COUNT,
                "options": options,
                "start": START_INDEX,
            }
        )
        result = self.get(endpoint=GET_ZONES_BY_HINT, ep_params=self.parameters)
        if not result.is_ok():
            self.format_error_raise_exception(
                log_loc=log_loc,
                result=result,
                exc_msg=f"Get zones with container: {container_id} by hint: {options} failed. Status code: {result.status_code}",
            )
        return result

    def is_address_allocated(
        self, mac_address: str, ip_address: str, configuration_id: int = IPAM_PARENT_ID
    ) -> Result:
        check_mac_address(mac_address=mac_address)
        check_ip_address(ip_address=ip_address)
        log_loc = log_location("is_address_allocated")
        self.set_params(
            {
                "macAddress": mac_address,
                "ipAddress": ip_address,
                "configurationId": configuration_id,
            }
        )
        result = self.get(endpoint=IS_ADDRESS_ALLOCATED, ep_params=self.parameters)
        if not result.is_ok():
            self.format_error_raise_exception(
                log_loc=log_loc,
                result=result,
                exc_msg=f"Check if Address Allocated (IP: {ip_address}, MAC: {mac_address}) failed. Status code: {result.status_code}",
            )
        return result

    def search_by_category(
        self,
        search_str: str,
        category: str = RESOURCE_RECORD,
        start_index: int = START_INDEX,
    ) -> Result:
        """
        See constants for CATEGORY constants options. Defaults to resourceRecords (RESOURCE_RECORD).
        :param search_str:
        :param category:
        :return:
        """
        log_loc = log_location("search_by_category")
        if category not in CATEGORY_CONSTS:
            raise BluecatAdapterException(f"Invalid category: {category}")
        self.set_params(
            {
                "category": category,
                "count": MAX_OBJ_RETURN_COUNT,
                "keyword": search_str,
                "start": start_index,
            }
        )
        result = self.get(endpoint=SEARCH_BY_CATEGORY, ep_params=self.parameters)
        if not result.is_ok():
            self.format_error_raise_exception(
                log_loc=log_loc,
                result=result,
                exc_msg=f"Search by category {category} and keyword: {search_str} failed. Status code: {result.status_code}",
            )
        return result

    def search_by_object_types(
        self, search_str: str, obj_types: list[str], start_index: int = START_INDEX
    ) -> Result:
        log_loc = log_location("search_by_object_types")

        if all(obj not in OBJ_TYPES for obj in obj_types):
            raise BluecatAdapterException(f"Invalid object type {obj_types}.")

        # Str format for input
        formatted_types = ""
        for obj in obj_types:
            formatted_types += f"{obj},"
        formatted_types = formatted_types[:-1]

        self.set_params(
            {
                "types": formatted_types,
                "count": MAX_OBJ_RETURN_COUNT,
                "keyword": search_str,
                "start": start_index,
            }
        )
        result = self.get(endpoint=SEARCH_BY_OBJECT_TYPES, ep_params=self.parameters)
        if not result.is_ok():
            self.format_error_raise_exception(
                log_loc=log_loc,
                result=result,
                exc_msg=f"Search by object type(s): {obj_types} on keyword: {search_str} failed. Status code: {result.status_code}",
            )
        return result

    # POST Endpoints
    def access_right(
        self,
        target_entity_id: int,
        workflow_lvl: str,
        deployment_allowed: bool,
        user_id: int,
        value: str,
        action: str = "add",
    ) -> Result:
        """
        Add or Update an Access Right. Default action is 'add'.
        :param target_entity_id:
        :param workflow_lvl:
        :param deployment_allowed:
        :param user_id:
        :param value:
        :param action:
        :return:
        """

        match action.lower():
            case "add":
                endpoint = ADD_ACCESS_RIGHT
            case "update":
                endpoint = UPDATE_ACCESS_RIGHT
            case _:
                raise BluecatAdapterException(
                    f"Invalid action: {action} for endpoint access_right"
                )

        log_loc = log_location(f"{action}_access_right")

        if workflow_lvl not in ["None", "Recommended", "Approve"]:
            raise BluecatAdapterException(
                f"Invalid Workflow Level: {workflow_lvl}. Must be 'None', 'Recommended', or 'Approve`."
            )
        if value not in ACCESS_CONSTS:
            raise BluecatAdapterException(
                f"Invalid access value: {value}. Must be one of {ACCESS_CONSTS}"
            )

        properties = (
            f"workflowLevel={workflow_lvl}|"
            f"deploymentAllowed={deployment_allowed.lower()}|"
            f"quickDeploymentAllowed=false"
        )

        self.set_params(
            {
                "entityId": target_entity_id,
                "overrides": "",
                "properties": properties,
                "userId": user_id,
                "value": value,
            }
        )
        result = self.post(endpoint=endpoint, ep_params=self.parameters)
        if not result.is_ok():
            self.format_error_raise_exception(
                log_loc=log_loc,
                result=result,
                exc_msg=f"{action} Access right for user: {user_id} on entity ID: {target_entity_id} failed. Status code: {result.status_code}",
            )
        return result

    def add_alias_record(
        self,
        alias_fqdn: str,
        linked_record: str,
        ttl: int,
        view_id: int,
        properties: str = None,
    ) -> Result:
        """
        Add an alias record to the provided linked record.
        :param alias_fqdn: The new alias FQDN.
        :param linked_record: The name of the linked(target) record.
        :param properties: Comments and user-defined fields.
        :param ttl: The Time-To-Live for this alias.
        :param view_id: The object ID for the parent view to which this record is being added.
        :return: The Result object containing the response.
        """
        log_loc = log_location("add_alias_record")
        check_fqdn(alias_fqdn)

        self.set_params(
            {
                "absoluteName": alias_fqdn,
                "linkedRecordName": linked_record,
                "properties": properties,
                "ttl": ttl,
                "viewId": view_id,
            }
        )
        result = self.post(endpoint=ADD_ALIAS_RECORD, ep_params=self.parameters)
        if not result.is_ok():
            self.format_error_raise_exception(
                log_loc=log_loc,
                result=result,
                exc_msg=f"Add Alias Record ({alias_fqdn}) --to-> ({linked_record}) failed. Status code: {result.status_code}",
            )
        return result

    # Leaving skelton in for now; don't think these will be used.
    # def add_device(self) -> Result:
    #     log_loc = log_location("add_device")
    #     self.set_params({
    #
    #     })
    #     result = self.post(endpoint=ADD_DEVICE, ep_params=self.parameters)
    #     if not result.is_ok():
    #         self.format_error_raise_exception(
    #             log_loc=log_loc, result=result,
    #             exc_msg=f" failed. Status code: {result.status_code}"
    #         )
    #     return result
    #
    # def add_entity(self) -> Result:
    #     log_loc = log_location("add_entity")
    #     self.set_params({
    #
    #     })
    #     result = self.post(endpoint=ADD_ENTITY, ep_params=self.parameters)
    #     if not result.is_ok():
    #         self.format_error_raise_exception(
    #             log_loc=log_loc, result=result,
    #             exc_msg=f" failed. Status code: {result.status_code}"
    #         )
    #     return result

    def add_external_host_record(
        self, ext_fqdn: str, view_id: int, properties: str = None
    ) -> Result:
        log_loc = log_location("add_external_host_record")

        # todo: check views in a more robust way?
        if view_id not in INT_EXT_VIEWS or view_id not in BASE_DOMAIN_VIEWS:
            raise BluecatAdapterException(f"Invalid view ID: {view_id}.")
        check_fqdn(ext_fqdn)

        self.set_params({"name": ext_fqdn, "properties": properties, "viewId": view_id})
        result = self.post(endpoint=ADD_EXTERNAL_HOST_RECORD, ep_params=self.parameters)
        if not result.is_ok():
            self.format_error_raise_exception(
                log_loc=log_loc,
                result=result,
                exc_msg=f"Add External FQDN ({ext_fqdn}) to view: {view_id} failed. Status code: {result.status_code}",
            )
        return result

    def add_generic_record(
        self,
        record_name: str,
        rdata: str,
        ttl: int,
        view_id: int,
        properties: str = None,
        rtype: str = "A",
    ) -> Result:
        log_loc = log_location("add_generic_record")

        if rtype not in RESOURCE_RECORDS_TYPES_FULL:
            raise BluecatAdapterException(f"Invalid record type: {rtype}.")
        if rtype != "A":
            raise BluecatAdapterException(
                f"Unintended Resource record type? Type not 'A', but is {rtype}."
            )
        if view_id not in BASE_DOMAIN_VIEWS or view_id not in INT_EXT_VIEWS:
            raise BluecatAdapterException(f"Invalid view ID: {view_id}.")

        check_ip_address(ip_address=rdata)

        self.set_params(
            {
                "absoluteName": record_name,
                "properties": properties,
                "rdata": rdata,
                "ttl": ttl,
                "type": rtype,
                "viewId": view_id,
            }
        )
        result = self.post(endpoint=ADD_GENERIC_RECORD, ep_params=self.parameters)
        if not result.is_ok():
            self.format_error_raise_exception(
                log_loc=log_loc,
                result=result,
                exc_msg=f"Add Generic Record ({rtype} -> {rdata}) failed. Status code: {result.status_code}",
            )
        return result

    def add_host_record(
        self,
        record_fqdn: str,
        addresses: list[str],
        ttl: int,
        view_id: int,
        properties: str = None,
        same_as_zone: bool = False,
    ) -> Result:
        """

        :param record_fqdn: The FQDN of the host record.
        :param addresses: List of addresses to tie to the host record.
        :param properties: The properties of the host record.
        :param ttl: The Time-To-Live of the record.
        :param view_id: The parent view in which to add the host record.
        :param same_as_zone: Boolean to determine if the record is Same as Zone or not.
        :return:
        """
        log_loc = log_location("add_host_record")

        if view_id not in BASE_DOMAIN_VIEWS or view_id not in INT_EXT_VIEWS:
            raise BluecatAdapterException(f"Invalid view ID: {view_id}.")

        for addr in addresses:
            check_ip_address(ip_address=addr)

        check_fqdn(fqdn=record_fqdn)
        record_fqdn = "." + record_fqdn if same_as_zone else record_fqdn

        self.set_params(
            {
                "absoluteName": record_fqdn,
                "addresses": addresses,
                "properties": properties,
                "ttl": ttl,
                "viewId": view_id,
            }
        )
        result = self.post(endpoint=ADD_HOST_RECORD, ep_params=self.parameters)
        if not result.is_ok():
            self.format_error_raise_exception(
                log_loc=log_loc,
                result=result,
                exc_msg=f"Add Host Record ({record_fqdn}) to view: {view_id} failed. Status code: {result.status_code}",
            )
        return result

    def add_mac_address(
        self,
        mac_address: str,
        properties: str = None,
        configuration_id: int = IPAM_PARENT_ID,
    ) -> Result:
        log_loc = log_location("add_mac_address")

        check_mac_address(mac_address=mac_address)

        self.set_params(
            {
                "configurationId": configuration_id,
                "macAddress": mac_address,
                "properties": properties,
            }
        )
        result = self.post(endpoint=ADD_MAC_ADDRESS, ep_params=self.parameters)
        if not result.is_ok():
            self.format_error_raise_exception(
                log_loc=log_loc,
                result=result,
                exc_msg=f"Add MAC Address {mac_address} failed. Status code: {result.status_code}",
            )
        return result

    def add_txt_record(
        self,
        record_fqdn: str,
        ttl: int,
        txt_data: str,
        view_id: int,
        properties: str = None,
    ) -> Result:

        log_loc = log_location("add_txt_record")

        check_fqdn(fqdn=record_fqdn)

        self.set_params(
            {
                "absoluteName": record_fqdn,
                "properties": properties,
                "ttl": ttl,
                "txt": txt_data,
                "viewId": view_id,
            }
        )
        result = self.post(endpoint=ADD_TXT_RECORD, ep_params=self.parameters)
        if not result.is_ok():
            self.format_error_raise_exception(
                log_loc=log_loc,
                result=result,
                exc_msg=f"Add TXT Record ({record_fqdn}) failed. Status code: {result.status_code}",
            )
        return result

    # Not implemented yet
    # def add_user(self) -> Result:
    #     log_loc = log_location("add_user")
    #     self.set_params({
    #
    #     })
    #     result = self.post(endpoint=ADD_USER, ep_params=self.parameters)
    #     if not result.is_ok():
    #         self.format_error_raise_exception(
    #             log_loc=log_loc, result=result,
    #             exc_msg=f" failed. Status code: {result.status_code}"
    #         )
    #     return result

    def add_zone(self, zone_fqdn: str, parent_id: int) -> Result:
        log_loc = log_location("add_zone")

        check_fqdn(fqdn=zone_fqdn)

        self.set_params(
            {
                "absoluteName": zone_fqdn,
                "parentId": parent_id,
                "properties": "deployable=true",
            }
        )
        result = self.post(endpoint=ADD_ZONE, ep_params=self.parameters)
        if not result.is_ok():
            self.format_error_raise_exception(
                log_loc=log_loc,
                result=result,
                exc_msg=f"Add Zone {zone_fqdn} under parent: {parent_id} failed. Status code: {result.status_code}",
            )
        return result

    def assign_ip4_address(
        self,
        action: str,
        properties: str,
        ip_address: str,
        configuration_id: int = IPAM_PARENT_ID,
        mac_address: str = None,
        host_info: str = None,
    ) -> Result:
        """
        Assign an IP address
        :param properties: The properties for the IP Address: "name=input_name", and more specific data. Check the Proteus API Docs under
        "POST /v1/assignIP4Address", parameter field "properties".
        :param mac_address: The MAC Address to add to the IP Address.
        :param ip_address: The IP Address you would like to assign.
        :param action: The action is one of the Assignment actions, for Static, Reserved, DHCP Reserved
        :param host_info: Single, or repeated CSV string(s) of: hostname,viewId,reverseFlag,sameAsZoneFlag
        with an example host_info like so: ex_host,123456,true,false,ex_host2,789101,true,true
        :param configuration_id: FIGURE THIS OUT
        :return:
        """
        # Todo: understand if config ID is the same thing
        log_loc = log_location("assign_ip4_address")

        if not mac_address and not host_info or (mac_address and host_info):
            raise BluecatAdapterException(
                f"You need to choose either a MAC Address or a host info field "
                f"to assign to this IP4Address."
            )

        if action not in [MAKE_STATIC, MAKE_RESERVED, MAKE_DHCP_RESERVED]:
            raise BluecatAdapterException(f"Invalid action: {action}")
        check_ip_address(ip_address=ip_address)

        # Todo: Re-add Host info section
        # host_split = host_info.split(',')
        # # if len(host_info) != 4:
        # #     raise BluecatAdapterException(f"Invalid host info {host_info} - "
        # #                                   f"Must be CSV and 4 values -- Multiple entries not yet implemented.")
        # # hostname = host_split[0]
        # # view_id = host_split[1]
        # reverse_flag = host_split[2]
        # same_as_zone = host_split[3]

        # TOdo: Improve 'name' in properties check
        # if '=' not in properties or properties.split('=')[0] != 'name':
        #     properties = "name=NoNameGiven|"+properties

        self.set_params(
            {
                "action": action,
                "configurationId": configuration_id,
                "ip4Address": ip_address,
                "properties": properties,
            }
        )
        if host_info:
            self.add_params({"hostInfo": host_info})
        if mac_address:
            self.add_params({"macAddress": mac_address})

        result = self.post(endpoint=ASSIGN_IP4_ADDRESS, ep_params=self.parameters)
        if not result.is_ok():
            self.format_error_raise_exception(
                log_loc=log_loc,
                result=result,
                exc_msg=f"Assign IP4Address {ip_address} failed. Status code: {result.status_code}",
            )
        return result

    def deploy_all_dns(self) -> str:
        """
        Deploy all DNS servers
        :return: Str: Success on success; on failure there is an exception.
        """
        for server in DNS_ALL:
            result = self.deploy_server(server_id=server)
            if not result.is_ok():
                raise BluecatAdapterException(f"Failed to deploy server: {server}")
            # Todo: Check that the "is_ok" pass is enough to feel that it's a successful deploy
            self.log(level="info", msg=f"Deployed {server} server successfully.")
        return "success"

    def deploy_server(self, server_id: int) -> Result:
        log_loc = log_location("deploy_server")

        if server_id not in DNS_ALL:
            raise BluecatAdapterException(f"Invalid server_id: {server_id}")

        self.set_params({"serverId": server_id})
        result = self.post(endpoint=DEPLOY_SERVER, ep_params=self.parameters)
        if not result.is_ok():
            self.format_error_raise_exception(
                log_loc=log_loc,
                result=result,
                exc_msg=f"Deploy Server failed. Status code: {result.status_code}",
            )
        return result

    # PUT Endpoints
    def change_state_ip4_address(
        self, address_id: int, mac_address: int = None, target_state: str = MAKE_STATIC
    ) -> Result:
        """
        Change the state of an IP address, by the Address ID given.
        :param address_id: The address ID of the IP Address to change.
        :param mac_address: The MAC address, provided it is needed (for DHCP Reserved and Reserved)
        :param target_state: One of: MAKE_STATIC, MAKE_RESERVED, MAKE_DHCP_RESERVED.
        :return:
        """
        log_loc = log_location("change_state_ip4_address")

        if target_state not in [MAKE_STATIC, MAKE_RESERVED, MAKE_DHCP_RESERVED]:
            raise BluecatAdapterException(f"Invalid action: {target_state}")

        self.set_params(
            {
                "addressId": address_id,
                "macAddress": mac_address,
                "targetState": target_state,
            }
        )
        result = self.put(endpoint=CHANGE_STATE_IP4_ADDRESS, ep_params=self.parameters)
        if not result.is_ok():
            self.format_error_raise_exception(
                log_loc=log_loc,
                result=result,
                exc_msg=f" failed. Status code: {result.status_code}",
            )
        return result

    def link_entities(
        self, entity_one_id: int, entity_two_id: int, properties: str
    ) -> Result:
        log_loc = log_location("link_entities")

        entity_one = self.get_entity_by_id(entity_one_id)
        if not entity_one.is_ok():
            raise BluecatAdapterException(f"Entity not found: {entity_one_id}")
        # todo: ensure the result['data'] is formatted like you expect

        # Todo: BIG -- create a mapping of allowable type to type links

        entity_two = self.get_entity_by_id(entity_two_id)
        if not entity_two.is_ok():
            raise BluecatAdapterException(f"Entity not found: {entity_two_id}")

        self.set_params({})
        result = self.put(endpoint=LINK_ENTITIES, ep_params=self.parameters)
        if not result.is_ok():
            self.format_error_raise_exception(
                log_loc=log_loc,
                result=result,
                exc_msg=f" failed. Status code: {result.status_code}",
            )
        return result

    def link_entities_ex(self) -> Result:
        # TODO: Also mirror above and figure if this is needed
        log_loc = log_location("link_entities_ex")
        self.set_params({})
        result = self.put(endpoint=LINK_ENTITIES_EX, ep_params=self.parameters)
        if not result.is_ok():
            self.format_error_raise_exception(
                log_loc=log_loc,
                result=result,
                exc_msg=f" failed. Status code: {result.status_code}",
            )
        return result

    def unlink_entities(self) -> Result:
        log_loc = log_location("unlink_entities")
        self.set_params({})
        result = self.put(endpoint=UNLINK_ENTITIES, ep_params=self.parameters)
        if not result.is_ok():
            self.format_error_raise_exception(
                log_loc=log_loc,
                result=result,
                exc_msg=f" failed. Status code: {result.status_code}",
            )
        return result

    def unlink_entities_ex(self) -> Result:
        log_loc = log_location("unlink_entities_ex")
        self.set_params({})
        result = self.put(endpoint=UNLINK_ENTITIES_EX, ep_params=self.parameters)
        if not result.is_ok():
            self.format_error_raise_exception(
                log_loc=log_loc,
                result=result,
                exc_msg=f" failed. Status code: {result.status_code}",
            )
        return result

    def move_resource_record(self, destination_fqdn: str, resource_id: int) -> Result:
        log_loc = log_location("move_resource_record")
        check_fqdn(fqdn=destination_fqdn)

        self.set_params(
            {"destinationZone": destination_fqdn, "resourceRecordId": resource_id}
        )
        result = self.put(endpoint=MOVE_RESOURCE_RECORD, ep_params=self.parameters)
        if not result.is_ok():
            self.format_error_raise_exception(
                log_loc=log_loc,
                result=result,
                exc_msg=f"Move Resource Record: {resource_id} to zone {destination_fqdn} failed. Status code: {result.status_code}",
            )
        return result

    def update(self, entity: dict) -> Result:
        log_loc = log_location("update")

        # The dict is an entity. Grab an entity by some API method, edit some attributes, and then send the object through
        # this update endpoint.
        self.set_params({})
        result = self.put(endpoint=UPDATE, data=entity)
        if not result.is_ok():
            self.format_error_raise_exception(
                log_loc=log_loc,
                result=result,
                exc_msg=f"Update on {entity['Id']} failed. Status code: {result.status_code}",
            )
        return result

    # Composite Methods
