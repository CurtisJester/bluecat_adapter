# BlueCat URL Constants
BLUECAT_REST = "hosname.here.com/api_stuff"

# BlueCat ID Constants
IPAM_PARENT_ID = ID_HERE

# DNS SERVERS and VIEWS Constants
DNS_ONE = 1234
DNS_ALL = [DNS_ONE]
DNS_INTERNAL_ID = 12345
DNS_EXTERNAL_ID = 56789
INT_EXT_VIEWS = [DNS_INTERNAL_ID, DNS_EXTERNAL_ID]
BASE_DOMAIN_EXTERNAL = 12333
BASE_DOMAIN_INTERNAL = 56788
BASE_DOMAIN_VIEWS = [BASE_DOMAIN_INTERNAL, BASE_DOMAIN_EXTERNAL]

# Search endpoints
CATEGORY_SEARCH = "searchByCategory"

# GET endpoints
DELETE_MAIN = "delete"
DELETE_ACCESS_RIGHT = "deleteAccessRight"
DELETE_WITH_OPTIONS = "deleteWithOptions"
BAMHEALTH = "bam/v1/health"
CUSTOM_SEARCH = "customSearch"
GET_IPV4 = "getIP4Address"
GET_PARENT = "getParent"
GET_ENTITY_BY_ID = "getEntityById"
GET_ENTITY_BY_NAME = "getEntityByName"
GET_LINKED_ENTITIES = "getLinkedEntities"
GET_ENTITIES = "getEntities"
GET_ENTITIES_BY_NAME = "getEntitiesByNameUsingOptions"
GET_ACCESS_BY_USER = "getAccessRightsForUser"
GET_ACCESS_BY_ENTITY = "getAccessRightsForEntity"
GET_ZONES_BY_HINT = "getZonesByHint"
GET_LINKED_NET_PROPS = "getNetworkLinkedProperties"
GET_ALIASES_BY_HINT = "getAliasesByHint"
GET_ALL_USED_LOCATIONS = "getAllUsedLocations"
GET_CONFIGURATION_GROUPS = "getConfigurationGroups"
GET_CONFIGURATION_SETTING = "getConfigurationSetting"
GET_CONFIGURATIONS_BY_GROUP = "getConfigurationsByGroup"
GET_ENTITIES_BY_NAME_USING_OPTIONS = "getEntitiesByNameUsingOptions"
GET_ENTITY_BY_CIDR = "getEntityByCIDR"
GET_ENTITY_BY_PREFIX = "getEntityByPrefix"
GET_ENTITY_BY_RANGE = "getEntityByRange"
GET_HOST_RECORDS_BY_HINT = "getHostRecordsByHint"
GET_IP4_NETWORKS_BY_HINT = "getIP4NetworksByHint"
GET_IP_RANGED_BY_IP = "getIPRangedByIP"
GET_MAC_ADDRESS = "getMACAddress"
GET_NETWORK_LINKED_PROPERTIES = "getNetworkLinkedProperties"
GET_NEXT_AVAILABLE_IP4_ADDRESS = "getNextAvailableIP4Address"
GET_USER_DEFINED_FIELDS = "getUserDefinedFields"
GET_ZONES_BY_HINT = "getZonesByHint"
IS_ADDRESS_ALLOCATED = "isAddressAllocated"
SEARCH_BY_CATEGORY = "searchByCategory"
SEARCH_BY_OBJECT_TYPES = "searchByObjectTypes"

# POST endpoints
ADD_ACCESS_RIGHT = "addAccessRight"
ADD_ALIAS_RECORD = "addAliasRecord"
ADD_DEVICE = "addDevice"
ADD_ENTITY = "addEntity"
ADD_EXTERNAL_HOST_RECORD = "addExternalHostRecord"
ADD_GENERIC_RECORD = "addGenericRecord"
ADD_HOST_RECORD = "addHostRecord"
ADD_TXT_RECORD = "addTXTRecord"
ADD_MAC_ADDRESS = "addMACAddress"
ADD_USER = "addUser"
POST_EXTERNAL_HOSTS = "addExternalHostRecord"
ADD_ZONE = "addZone"
ASSIGN_IP4_ADDRESS = "assignIP4Address"
DEPLOY_SERVER = "deployServer"
CHANGE_STATE_IP4_ADDRESS = "changeStateIP4Address"
LINK_ENTITIES = "linkEntities"
LINK_ENTITIES_EX = "linkEntitiesEx"
MOVE_RESOURCE_RECORD = "moveResourceRecord"
UNLINK_ENTITIES = "unlinkEntities"
UNLINK_ENTITIES_EX = "unlinkEntitiesEx"
UPDATE = "update"
UPDATE_ACCESS_RIGHT = "updateAccessRight"


# CATEGORY Constants
CONFIGURATION = "Configuration"
DHCP_ZONES = "DHCPZones"
GSS = "GSS"
IP4_OBJECTS = "IP4Objects"
IP6_OBJECTS = "IP6Objects"
MACPOOL_OBJECTS = "MACPoolObjects"
SERVERGROUP = "ServerGroup"
TFTP_OBJECTS = "TFTPObjects"
TSIG_KEYS = "TSIGKeys"
ADMIN = "admin"
ALL = "all"
DEPLOYMENT_OPTIONS = "deploymentOptions"
DEPLOYMENT_ROLES = "deploymentRoles"
DEPLOYMENT_SCHEDULER = "deploymentSchedulers"
DHCPCLASSES_OBJECTS = "dhcpClassObjects"
DHCPNACPOLICY_OBJECTS = "dhcpNACPolicies"
RESOURCE_RECORD = "resourceRecords"
SERVERS = "servers"
TAGS = "tags"
TASKS = "tasks"
VENDOR_PROFILES = "vendorProfiles"
VIEWS_ZONES = "viewZones"
CATEGORY_CONSTS = [
    CONFIGURATION,
    DHCP_ZONES,
    GSS,
    IP4_OBJECTS,
    IP6_OBJECTS,
    MACPOOL_OBJECTS,
    SERVERGROUP,
    TFTP_OBJECTS,
    TSIG_KEYS,
    ADMIN,
    ALL,
    DEPLOYMENT_OPTIONS,
    DEPLOYMENT_ROLES,
    DEPLOYMENT_SCHEDULER,
    DHCPCLASSES_OBJECTS,
    DHCPNACPOLICY_OBJECTS,
    RESOURCE_RECORD,
    SERVERS,
    TAGS,
    TASKS,
    VENDOR_PROFILES,
    VIEWS_ZONES,
]

# ACCESS RIGHTS Constants
ADD = "AddAccess"
CHANGE = "ChangeAccess"
FULL = "FullAccess"
HIDE = "HideAccess"
VIEW = "ViewAccess"
ACCESS_CONSTS = [ADD, CHANGE, FULL, HIDE, VIEW]

# IP ASSIGNMENT Constants
MAKE_DHCP_RESERVED = "MAKE_DHCP_RESERVED"
MAKE_RESERVED = "MAKE_RESERVED"
MAKE_STATIC = "MAKE_STATIC"

# LINK ENTITIES Constants
# TODO: fix "ip or server"
LINK_ENTITIES_TYPES = [
    "Any entity",
    "Tag",
    "MAC pool",
    "MAC address",
    "User",
    "User group",
    "Location",
    "IP or server object",
    "Server group",
    "Server",
]


# RESOURCE RECORD Constants
RESOURCE_RECORDS_TYPES_FULL = [
    "A",
    "A6",
    "AAAA",
    "AFSDB",
    "APL",
    "CAA",
    "CERT",
    "DHCID",
    "DNAME",
    "DNSKEY",
    "DS",
    "ISDN",
    "KEY",
    "KX",
    "LOC",
    "MB",
    "MG",
    "MINFO",
    "MR",
    "NS",
    "NSAP",
    "PX",
    "RP",
    "RT",
    "SINK",
    "SSHFP",
    "TLSA",
    "WKS",
    "X25",
]

# PUT endpoints
PUT_UPDATE = "update"

# Program Operation Constants
MAX_OBJ_RETURN_COUNT = 10
MAX_COUNT = 1000
START_INDEX = 0
RECORD_LIST = [
    "ResourceRecord",
    "TXTRecord",
    "SRVRecord",
    "RecordWithLink",
    "MXRecord",
    "NAPTRRecord",
    "AliasRecord",
]
NET_OBJ_TYPES = ["IP4Block", "IP4Address"]
NET_RANGE_TYPES = ["IP4Block", "IP4Network", "DHCP4Range"]
OBJ_TYPES = [
    "AliasRecord",
    "Configuration",
    "CustomOptionDef",
    "DenyMACPool",
    "DeploymentScheduler",
    "Device",
    "DeviceSubtype",
    "DeviceType",
    "DHCPDeploymentRole",
    "DHCPMatchClass",
    "DHCPRawOption",
    "DHCPServiceOption",
    "DHCPSubClass",
    "DHCPV4ClientOption",
    "DHCP4Range",
    "DHCPV6ClientOption",
    "DHCP6Range",
    "DHCPV6RawOption",
    "DHCPV6ServiceOption",
    "DNSDeploymentRole",
    "DNSOption",
    "DNSRawOption",
    "DNSSECSigningPolicy",
    "Entity",
    "EnumNumber",
    "EnumZone",
    "ExternalHostRecord",
    "GenericRecord",
    "HINFORecord",
    "HostRecord",
    "InternalRootZone",
    "IP4Address",
    "IP4Block",
    "IP4IPGroup",
    "IP4Network",
    "IP4NetworkTemplate",
    "IP4Ranged",
    "IP4ReconciliationPolicy",
    "IP6Address",
    "IP6Block",
    "IP6Network",
    "InterfaceID",
    "Kerberos",
    "KerberosRealm",
    "LDAP",
    "Location",
    "MACAddress",
    "MACPool",
    "MXRecord",
    "NAPTRRecord",
    "NetworkInterface",
    "NetworkServerInterface",
    "PublishedServerInterface",
    "Radius",
    "RecordWithLink",
    "ResourceRecord",
    "ResponsePolicy",
    "RPZone",
    "Server",
    "ServerGroup",
    "SRVRecord",
    "StartOfAuthority",
    "Tag",
    "TagGroup",
    "TFTPDeploymentRole",
    "TFTPFile",
    "TFTPFolder",
    "TFTPGroup",
    "TSIGKey",
    "TXTRecord",
    "User",
    "UserGroup",
    "VendorClientOption",
    "VendorOptionDef",
    "VendorProfile",
    "View",
    "VirtualInterface",
    "Zone",
    "ZoneTemplate",
]
# EMPTY OBJECT
EMPTY_OBJ = {"id": 0, "name": None, "type": None, "properties": None}

# OBJ TYPE MISMATCH STRING
OBJ_MISMATCH = "Type: {obj_type} is not a valid object type. Check Constants file for available types."

