import logging
import os 
import types
import yaml
import copy
import random
from functools import reduce


""" Constants and more """
__location__ = os.path.realpath(os.path.join(os.getcwd(), os.path.dirname(__file__))) + '/'
id_name_mapping = {1: "Ethernet",
                   8: "IPv4"}
multipliers = {'b': 1, 'w': 2, 'd': 4}
apriori_rules = {'IP4.header.source_ip': 'DHCP.header.siaddr',
              'IP4.header.destination_ip': 'DHCP.header.yiaddr',
              'Ethernet.header.src': 'ARP.header.sha',
              'Ethernet.header.dest': 'ARP.header.tha'}

IMPORT_LOC = ""

# naming conventions
METAFILE = "protocols.yml"
META_CFG = dict()
PROTOCOL_LIB = "protocol_lib/"
LOADED_PROTOCOLS = dict()
HANDLER_LOC = "handler"
CHECKSUM_LOC = "checksum"
APRIORI = "apriori"

# declares
PREFIX_LEN_BIN = 32
PREFIX_LEN = 4
PREFIX = 32 * '1'
DICE_MAX = 2**8

# fields
META = "meta"
HEADER = "header"
BODY = "body"
PKT = "_packet"

#body
MAX_LEN = "max"

# meta fields
ID = "id"
ENDIAN = "endian"
COMPRESSION = "compression"
NO_COMP = "no_comp"
HEADER_LEN = "header_len"
FIELD_ENDIAN = "field_endian"
UNCOMPRESSED_LEN = "uncompressed_len"
FRAGMENT_NR = 0
HANDSHAKE = "handshake"

BIG_ENDIAN = "be"
LITTLE_ENDIAN = "le"

# header fields
TYPE ="type"
SIZE = "size"
SIZE_PTR = "size_ptr"
DOC = "doc"
DEFAULT = "default"
VALUE = "value"
HANDLER = "handler"
CHECKSUM = "checksum"
BITMASK = "bitmask"
COND_FIELD = "cond_field" #deprecated?
COND_HANDLER = "cond_handler"
REFERENCE = "reference"
STREAM_POINTER = "_pointer"
STREAM_LEN = "_len"
STREAM_DATA = "_written_data"
ACTION = 'action'
OPAQUE = 'opaque'
VAL_PREFIX = 'prefix'
OPTIONS = 'options'

# field types
T_NESTED = "nested"
T_CONDITIONAL = "conditional"
T_CONDITION = "condition"
T_CHECKSUM = "checksum"
T_LENGTH = "length"
T_FUZZED = "fuzzed"
T_DATA = "data"
T_POINTER = "pointer"
T_HANDLER = "handler"
T_REFERENCE = "reference"

# actions
A_COMPRESSION = 'compression'
A_FRAGMENTATION = 'fragmentation'

# pointer
POINT_TO_NESTED = 'point_to_nested'

# fuzzed options
F_EPHEMERAL = "ephemeral"

# handler optiones
H_RESOLVED = "_resolved_header"

# conditional options
C_MASKED = "_masked"
COMPRESSED = "_compressed"

# length/checksum scopes
S_NESTED = "nested"
S_HEADER = "header"
S_BODY = "body"
S_EVERYTHING = "all"

# length options
L_MODIFIER = "modifier"
L_SCOPE = "scope"
L_FORMAT = "format"
L_HEADER = S_HEADER
L_BODY = S_BODY
L_EVERYTHING = S_EVERYTHING

# Protocol specific constants
IEEE802154_DATA = 1
IEEE802154_COMMAND = 2
IEEE802154_BEACON = 0
IEEE802154_ACK = 3

# faults
DEFAULT_PROBABILITY = 10
LENGTH_WEIGHT = 12
HANDLER_WEIGHT = 2
CONDITION_WEIGHT = 2
CONDITIONAL_WEIGHT = 2
REFERENCE_WEIGHT = 1
POINTER_WEIGHT = 1
FUZZED_WEIGHT = 0
DATA_WEIGHT = 1
CHECKSUM_WEIGHT = 0
NESTED_WEIGHT = 20
weight_table = {
    "length": LENGTH_WEIGHT,
    "handler": HANDLER_WEIGHT,
    "condition": CONDITION_WEIGHT,
    "conditional": CONDITIONAL_WEIGHT,
    "reference": REFERENCE_WEIGHT,
    "pointer": POINTER_WEIGHT,
    "fuzzed": FUZZED_WEIGHT,
    "data": DATA_WEIGHT,
    "checksum": CHECKSUM_WEIGHT,
    "nested": NESTED_WEIGHT
}

""" Helper functions """
def zero_rand(n: int) -> bytes:
    """ Return zero bytes """
    return n * b'\x00'


def be_place_data(data: int, bit_len: int):
    """ be data = data """
    return data


def le_place_data(data: int, bit_len: int):
    """ Swap endianess of data so it can be placed """
    actual_byte_len = ((len(hex(data)) -2) // 2) + ((len(hex(data)) -2) % 2)
    b_data = data.to_bytes(actual_byte_len, "big")

    if len(b_data) > 4:
        if len(b_data) % 4:
            b_data =b'\x00' * (4 - len(b_data) % 4) + b_data         
        le_res = b''
        for i in range(0, len(b_data), 4):
            slice = b_data[i:i+4]
            le_res += slice[::-1]
        if bit_len // 8 < len(le_res):
            le_res[-(bit_len//8):]

        return int.from_bytes(le_res, "big")

    if bit_len // 8 < len(b_data):
        b_data[-(bit_len//8):]
    
    return int.from_bytes(b_data, "little")


def resolve_checksum(field: dict, handler_key: str, store=True)-> types.FunctionType:
    """
    Wrapper for resolve_handler to instead resolve a checksum function
    """
    return resolve_handler(field, handler_key, store=store, module=CHECKSUM_LOC)


def resolve_handler(field: dict, handler_key: str, store=True, module=HANDLER_LOC) -> types.FunctionType:
    """
    resolve a handler name to its actual function; assuming it exists in the handler module

    Returns:
        A pointer to the function
    """   
    import importlib
    try:
        if not IMPORT_LOC:
            mod = importlib.import_module(module)
        else:
            mod = importlib.import_module(IMPORT_LOC+'.' + module)

        func_obj = getattr(mod, field[handler_key])
    except (ModuleNotFoundError, AttributeError):
        import traceback
        traceback.print_exc()
        func_obj = zero_bytes
    
    if store:
        field[H_RESOLVED] = func_obj
    return func_obj


def zero_bytes(*any):
    """
    Fallback if handler function is not implemented
    """
    return 10 * b'\x00'


def protocol_id_by_name(protocol: str) -> int:
    """ Get a protocol id from its name """
    global META_CFG
    if not META_CFG:
        META_CFG = load_config_deep(__location__ + PROTOCOL_LIB + METAFILE)
    for name, id_val in META_CFG["name_id_mapping"].items():
        if name == protocol:
            return id_val
        
    return 0


DUP = "DUP"
def resolve_protocol_id(protocol: str or int):
    """ Given a protocol return its name """
    if type(protocol) == str:
        return protocol
    global META_CFG
    if not META_CFG:
        META_CFG = load_config_deep(__location__ + PROTOCOL_LIB + METAFILE)
    for name, id_val in META_CFG["name_id_mapping"].items():
        if id_val == protocol:
            if DUP in name:
                return '_'.join([x for x in name.split('_')[1:]])
            
            return name

    # ERROR    
    return None


MODULE=None
IMPORTED_HANDLERS=dict()
def import_parsing_handler(name):
    """ Return function pointer to a handler that is given by its name """
    global MODULE, IMPORTED_HANDLERS
    if name in IMPORTED_HANDLERS:
        return IMPORTED_HANDLERS[name]
    if not MODULE:
        import importlib
        try:
            if not get_import_loc():
                mod = importlib.import_module('parsing_handler')
            else:
                mod = importlib.import_module(get_import_loc() +'.parsing_handler')
            MODULE = mod
            
        except (ModuleNotFoundError, AttributeError):
            #print(f"No handler found  for {name}")
            return None
        
    try: 
        handler = getattr(MODULE, name)
    except (ModuleNotFoundError, AttributeError):
        #print(f"No handler found  for {name}")
        return None
    IMPORTED_HANDLERS[name] = handler
    return handler


def add_handler(name, handler):
    global IMPORTED_HANDLERS
    IMPORTED_HANDLERS[name] = handler


def get_filename(protocol: str):
    """ Get filename of the protocol descrition giving a protocol name """
    global META_CFG
    if not META_CFG:
        META_CFG = load_config_deep(__location__ + PROTOCOL_LIB + METAFILE)
    return META_CFG['name_file_mapping'][protocol]


def load_protocol(protocol: str or int):
    """ Given a protocol name load the contents of the protocol description """
    if type(protocol) == int:
        protocol = resolve_protocol_id(protocol)
    global LOADED_PROTOCOLS
    if protocol not in LOADED_PROTOCOLS:
        LOADED_PROTOCOLS[protocol] = load_config_deep(__location__ + PROTOCOL_LIB + get_filename(protocol))    
    return copy.deepcopy(LOADED_PROTOCOLS[protocol])


OUTPUT_CONTENTS = dict()
WRITE_TRIES = 0
SAVE_AFTER = 20
def load_output_file(filename: str) -> dict:
    """ load the contents of an (output) file """
    global OUTPUT_CONTENTS
    if OUTPUT_CONTENTS:
        # Do we need to return copy?
        return OUTPUT_CONTENTS
    return load_config_deep(filename)


def save_to_output_file(contents: dict, filename: str, force_save=False):
    """ Write contents to an output file, buffer it if its not the nth try or force save is on """
    global OUTPUT_CONTENTS, WRITE_TRIES, SAVE_AFTER
    OUTPUT_CONTENTS = contents
    WRITE_TRIES += 1
    if force_save or WRITE_TRIES == SAVE_AFTER:
        WRITE_TRIES = 0
        save_config(contents, filename)


# getter setter; multiple scenarios:
# we have an indiviual field and want to get or set something
def get_field_info(field: dict, entry: str):
    """ get data at a key (entry) in a field """
    return field[entry]

def set_field_info(field: dict, entry: str, data):
    """ set data at a key (entry) in a field """
    field[entry] = data
    return

def set_header_field_size(layer: dict, name: str, data):
    """ Set size field of a headfiled given by its name """
    if HEADER in layer:
        set_field_size(layer[HEADER][name], layer, data)
    else:
        if name in layer: # already received a header
            set_field_size(layer[name], layer, data)
    return

def set_field_size(field: dict, layer: dict, data):
    """ Actually set the size field depending the data length """
    bitsize = 0
    if type(data) == int:
        bitsize = data * 8
    else:
        bitsize = int(data[1:])
    field[SIZE] = data
    field[STREAM_LEN] = bitsize
    layer[META]['dirty'] = 1
    return

# we have the entire layer and want to get or set a header field
def set_header_field(layer: dict, name: str, entry: str, data):
    """ Set data of a header field """
    if HEADER in layer:
        layer[HEADER][name][entry] = data
    else:
        if name in layer: # already received a header
            layer[name][entry] = data

    return

def get_header_field(layer: dict, name: str, entry: str):
    """ Get data of a header field """
    if HEADER in layer:
        return layer[HEADER][name][entry]
    if name in layer: # already received a header
        return layer[name][entry]

def set_field_type(field: dict, new_type: str):
    """ Set type data of field """
    field[TYPE] = new_type
    return

def get_field_type(field: dict) -> str:
    """ Get type data of field """
    return field[TYPE]


def get_bitsize(field: dict):
    """ Get size of filed's data in bits """
    size = field[SIZE]
    if type(size) == int:
        return size * 8
    
    return int(size[1:])

def get_bytesize(field: dict):
    """ Get size of filed's data in bytes """
    size = field[SIZE]
    if type(size) == int:
        return size
    
    # make sure value is rounded UP
    return -((-1 * int(size[1:])) // 8)

def to_int(bytez: bytes) -> int:
    """
    Transfrom a bytestring to a big endian integer
    """
    return int.from_bytes(bytez, "big")

def le_to_bytes(val: int) -> bytes:
    """    
    Transfrom a little endian integer to bytestring
    """
    be_bytes = bytes.fromhex(((len(hex(val)[2:]) % 2) * '0') +  hex(val)[2:])
    le_bytes = b''.join([be_bytes[i:i+4][::-1] for i in range(0, len(be_bytes), 4)])
    return le_bytes

def bitstring_to_bytes(s: str) -> bytes:
    """ Turn a bitstring into bytes """
    return int(s, 2).to_bytes((len(s) + 7) // 8, byteorder='big')


def int_to_bytes(val: int) -> bytes:
    """ Turn looooong int to big endian byte string """
    be_bytes = bytes.fromhex(((len(hex(val)[2:]) % 2) * '0') +  hex(val)[2:])
    return be_bytes

def bytes_change_endianess_32(val: bytes) -> bytes:
    """ Change endianess of bytestring """
    val = val + b'\x00' * ((4 - len(val) % 4) % 4)
    res = b''
    for i in range(0, len(val), 4):
        res += val[i:(i+4)][::-1]

    return res

def is_not_unpack(field: dict):
    """ For packet parsing return whether a field needs further parsing """
    if ((not SIZE in field or get_field_info(field, SIZE) == 0) and not get_field_info(field, TYPE) == T_NESTED or 
        (COMPRESSED in field and get_field_info(field, COMPRESSED) == True)):
        return True
    return False

def remove_trailing_zeroes(packet: bytes) -> bytes:
    """ Remove trailing zeroes from a bytestring """
    if not packet:
        return packet
    cur_len = len(packet)
    while packet[cur_len-1] == 0:
        cur_len -= 1
        if cur_len -1 < 0:
            return b''

    return packet[:cur_len]


#################################
#           yml stuff           #
#################################
tmp_cfg_str = "/tmp/.tmp_cfg.yml"
def load_config_from_str(input_data):
    """ Load yml in strung representation to a dict format """
    with open(tmp_cfg_str, "w") as f:
        f.write(input_data)

    if not os.path.isfile(tmp_cfg_str):
        return {}
    with open(tmp_cfg_str, 'rb') as infile:
        config = yaml.load(infile, Loader=yaml.FullLoader)

    if config is None:
        return {}
    return config 

def load_config_deep(path):
    """ HElper function that loads content from a yml file to a dict """
    if not os.path.isfile(path):
        return {}
    with open(path, 'rb') as infile:
        config = yaml.load(infile, Loader=yaml.FullLoader)
    if config is None:
        return {}
    return resolve_config_includes(config, path)

def load_config_from_handle(handle):
    """ Helper function that loads content from a yml file given a file handle """
    config = yaml.load(handle, Loader=yaml.FullLoader)
    if config is None:
        return {}
    return resolve_config_includes(config, path)

def resolve_config_includes(config, base_path):
    """
    Recursively resolves a config file, adjusting paths along
    the way
    """
    if 'include' in config:
        # Merge config files listed in 'include' in listed order
        # Root file gets priority
        newconfig = {}
        for f in config['include']:
            if not f.startswith("/"):
                # Make configs relative to the including config file
                cur_dir = os.path.dirname(base_path)
                f = os.path.abspath(os.path.join(cur_dir, f))

            with open(f, 'rb') as infile:
                other_config_snippet = yaml.load(infile, Loader=yaml.FullLoader)
            adjust_config_relative_paths(other_config_snippet, f)
            other_config_snippet = resolve_config_includes(other_config_snippet, f)
            _merge_dict(newconfig, other_config_snippet)
        _merge_dict(newconfig, config)
        config = newconfig
    return config

def adjust_config_relative_paths(config, base_path):
    # "./"-prefixed paths to properly resolve relative to config snippet
    if 'memory_map' not in config:
        return

    for _, region in config['memory_map'].items():
        if 'file' in region and region['file'].startswith("./"):
            region['file'] = os.path.join(os.path.dirname(base_path), region['file'])

def _merge_dict(dct, merge_dct):
    for k, _ in merge_dct.items():
        if (k in dct and isinstance(dct[k], dict)
                and isinstance(merge_dct[k], dict)):
            _merge_dict(dct[k], merge_dct[k])
        else:
            dct[k] = merge_dct[k]
    return

def save_config(config_map, dest_yml_path):
    """ Write dict as a yml file, given a file name"""
    # Use hex representation of numbers in generated yml file
    def hexint_presenter(dumper, data):
        return dumper.represent_int(hex(data))
    yaml.add_representer(int, hexint_presenter)

    with open(dest_yml_path, "w") as f:
        f.write(yaml.dump(config_map, default_flow_style=False))

def save_config_to_handle(config_map, f):
    """ Write dict as a yml file given a file handle"""
    # Use hex representation of numbers in generated yml file
    def hexint_presenter(dumper, data):
        return dumper.represent_int(hex(data))
    yaml.add_representer(int, hexint_presenter)

    f.write(yaml.dump(config_map, default_flow_style=False))


def set_import_loc(location: str):
    """ Helper to set import location """
    global IMPORT_LOC
    IMPORT_LOC = location

def get_import_loc():
    """ Helper to get import location """
    global IMPORT_LOC
    return IMPORT_LOC

############################
### Network tree related ###
############################
""" Initialize the different network stacks """
def modbus_init():
    phy_tree = Tree("Modbus")
    return phy_tree

def sixlowpan_init():
    phy_tree = Tree("IEEE802154_PHY")
    mac_ack_tree = Tree("6lowpan_MAC_Ack")
    mac_data_tree = Tree("6lowpan_MAC_Data")
    mac_beacon_tree = Tree("6lowpan_MAC_Beacon")
    mac_command_tree = Tree("6lowpan_MAC_Command")
    sixlowpan_frag_tree = Tree("6lowpan_mesh_frag", chain=True)
    sixlowpan_tree = Tree("6lowpan")
    udp_tree = Tree("UDP")
    tcp_tree = Tree("TCP")
    coap_tree = Tree("COAP")
    icmp6_tree = Tree("ICMP6")
    snmp_tree = Tree("SNMP")
    http_tree = Tree("HTTP")

    phy_tree.set_children([mac_ack_tree, mac_beacon_tree, mac_data_tree, mac_command_tree])
    mac_data_tree.set_children([sixlowpan_frag_tree])
    sixlowpan_frag_tree.set_children([sixlowpan_tree])
    sixlowpan_tree.set_children([udp_tree, icmp6_tree, tcp_tree])
    udp_tree.set_children([coap_tree, snmp_tree])
    tcp_tree.set_children([http_tree])
    
    return phy_tree

def tcpip_init():
    eth_tree = Tree("Ethernet")
    ip_tree = Tree("IP4")
    ip6_tree = Tree("IP6")
    arp_tree = Tree("ARP")
    tcp_tree = Tree("TCP")
    http_tree = Tree("HTTP")
    coap_tree = Tree("COAP")
    udp_tree = Tree("UDP")
    dhcp_tree = Tree("DHCP")
    icmp6_tree = Tree("ICMP6")
    icmp4_tree = Tree("ICMP4")
    igmp_tree = Tree("IGMP")
    snmp_tree = Tree("SNMP")

    eth_tree.set_children([ip_tree, ip6_tree, arp_tree])
    ip_tree.set_children([udp_tree, tcp_tree, icmp4_tree, igmp_tree])
    ip6_tree.set_children([udp_tree, tcp_tree, icmp6_tree])
    udp_tree.set_children([dhcp_tree, coap_tree, snmp_tree])
    tcp_tree.set_children([http_tree])

    return eth_tree

def ble_init():
    phy_tree = Tree("BLE_PHY")
    adv_channel = Tree("BLE_adv_channel_pdu")
    data_channel = Tree("BLE_data_channel_pdu")
    adv_ind = Tree("BLE_adv_ADV_IND")
    adv_direct_ind = Tree("BLE_adv_ADV_DIRECT_IND")
    adv_nonconn_ind = Tree("BLE_adv_ADV_NONCONN_IND")
    adv_scan_ind = Tree("BLE_adv_ADV_SCAN_IND")
    adv_ext_ind = Tree("BLE_adv_ADV_EXT_IND")
    aux_adv_ind = Tree("BLE_adv_AUX_ADV_IND")
    aux_sync_ind = Tree("BLE_adv_AUX_SYNC_IND")
    aux_chain_ind = Tree("BLE_adv_AUX_CHAIN_IND")
    connect_ind = Tree("BLE_adv_CONNECT_IND")
    aux_connect_req = Tree("BLE_adv_AUX_CONNECT_REQ")
    aux_connect_rsp = Tree("BLE_adv_AUX_CONNECT_RSP")
    adv_scan_req = Tree("BLE_adv_SCAN_REQ")
    adv_scan_rsp = Tree("BLE_adv_SCAN_RSP")
    aux_scan_req = Tree("BLE_adv_AUX_SCAN_REQ")
    aux_scan_rsp = Tree("BLE_adv_AUX_SCAN_RSP")


    phy_tree.set_children([adv_channel, data_channel])
    adv_channel.set_children([adv_ind, adv_direct_ind, adv_nonconn_ind, adv_scan_ind, adv_ext_ind, 
                              aux_adv_ind, aux_sync_ind, aux_chain_ind, connect_ind, aux_connect_req, 
                              aux_connect_rsp, adv_scan_req, adv_scan_rsp, aux_scan_req, aux_scan_rsp])

    return phy_tree


class Tree:
    """ Class that represents a network stack """
    _children: list
    _data: str
    _chain_next_one: bool
    def __init__(self, data: str, chain: bool=False):
        self._children = list()
        self._data = data
        self._chain_next_one = chain

    def get_name(self):
        return self._data

    def set_children(self, children):
        self._children = children

    def get_children(self):
        return self._children
    
    def get_child_names(self):
        return [x._data for x in self._children]
   

    def find_node(self, name: str):
        if name == self._data:
            return self
        
        for child in self.get_children():
            res = child.find_node(name)
            if res:
                return res

        return None

    def print_tree(self, tab=''):
        if not self._children:
            print(f"{tab}I, {self._data} am just a simple LEAVE")
            return
        print(f"{tab}I, {self._data} have {len(self._children)} children: {', '.join([x._data for x in self._children])}")
        for child in self._children:
            child.print_tree(tab + '\t')
        return


def is_leaf(tree: Tree, node: str) -> bool:
    tree_node = tree.find_node(node)
    
    if not tree_node or tree_node.get_children:
        return False
    
    return True
