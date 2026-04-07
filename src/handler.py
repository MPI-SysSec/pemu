from .utils import *

def default_handler(field: dict, layer: dict, upper_layer: dict, get_bytes: types.FunctionType) -> int:
    """
    Small handler showing the interface for implementing handlers. 
    The arguments should allow the handler to access all necessary information. 

    Args:
        field: dictionary of the field the handler function is executed from
        layer: the entire current layer of the packet (which contains the field)
        uppper_layer: the next upper layer; i.e., the layer assembled previous to the current on
        get_bytes: Callback to access fuzzer bytes

    Returns:
        Result of the handler's calculations as an integer
    """

    return 0xffffffff


# UDP
def handle_udp_source (field: dict, layer: dict, upper_layer: dict, get_bytes: types.FunctionType) -> int:
    """ Handler for the UDP source port - For most protocols it does not matter but for DHCP """
    if META in upper_layer and resolve_protocol_id(upper_layer[META][ID]) == "DHCP":
        return protocol_id_by_name("DUP_DHCP")
    if VALUE in field:
        return field[VALUE]
    
    # if no fixed val -> fuzzing data
    length = get_bytesize(field)
    return int.from_bytes(get_bytes(length), "big")


# TCP
def handle_tcp_option(field: dict, layer: dict, upper_layer: dict, get_bytes: types.FunctionType) -> int:
    """ Handle different TCP options """
    if C_MASKED in field and field[C_MASKED] == True:
        # If we sent a packet without an option the option field is masked and we need to reset it
        field[C_MASKED] = False
        layer[HEADER]['option_type'][C_MASKED] = False
        layer[HEADER]['option_length'][C_MASKED] = False
        layer[HEADER]['option_padding'][C_MASKED] = False

        dice = int.from_bytes(get_bytes(1), "big")
        val = layer[HEADER]['option_type'][OPTIONS][dice % len(layer[HEADER]['option_type'][OPTIONS])]
        if val == -1:
            val = dice

        layer[HEADER]['option_type'][VALUE] = val
        layer[HEADER]['option_type'][STREAM_DATA] = f"{val:0{layer[HEADER]['option_type'][STREAM_LEN]}b}"[-layer[HEADER]['option_type'][STREAM_LEN]:] 
        layer[META][HEADER_LEN]
        layer[META][HEADER_LEN] += 2 * 8 + field[SIZE] * 8 + layer[HEADER]['option_padding'][SIZE] * 8
        layer[META]['dirty'] = 1

    option_type = layer[HEADER]['option_type'][VALUE]
    size = 0

    if option_type == 2 or option_type == 28:
        size = 4
    elif option_type == 3:
        size = 3
    elif option_type == 4:
        size = 2
    elif option_type == 5:
        lens = [10, 18, 26, 34]
        size = lens[int.from_bytes(get_bytes(1), "big") % len(lens)]
    elif option_type == 8:
        size = 10
    elif option_type == 29 or option_type == 30:
        size = int.from_bytes(get_bytes(1), "big") % 40
    else:
        # No option appended
        field[C_MASKED] = True
        layer[HEADER]['option_type'][C_MASKED] = True
        layer[HEADER]['option_length'][C_MASKED] = True
        layer[HEADER]['option_padding'][C_MASKED] = True
        layer[META][HEADER_LEN] -= 2 * 8 + field[SIZE] * 8 + layer[HEADER]['option_padding'][SIZE] * 8
        return 0
    
    # We chose an option, now build the packet
    field[C_MASKED] = False
    layer[HEADER]['option_type'][C_MASKED] = False
    layer[HEADER]['option_length'][C_MASKED] = False

    layer[META][HEADER_LEN] -= field[STREAM_LEN]
    field[SIZE] = size
    field[STREAM_LEN] = field[SIZE] * 8
    layer[META]['dirty'] = 1
    layer[META][HEADER_LEN] += field[STREAM_LEN]

    # Add padding
    needed_padding = (4 - ((size + 2) % 4)) % 4  # plus type and length
    layer[META][HEADER_LEN] -= field[STREAM_LEN]
    set_header_field_size(layer, 'option_padding', needed_padding)
    layer[HEADER]['option_padding'][STREAM_DATA] = (needed_padding * 8) * '0'

    layer[META][HEADER_LEN] += field[STREAM_LEN]
   
    return int.from_bytes(get_bytes(size), "big")
    

def handle_ack_sqn(field: dict, layer: dict, upper_layer: dict, get_bytes: types.FunctionType) -> int:
    """
    Extract current ACK/SQN value and increment it by one; or create a new one
    """
    if STREAM_DATA in field:
        # increment by one
        return int(field[STREAM_DATA], 2) + 1

    # need new value, first check if there is an apriori value
    if VALUE in field:
        return field[VALUE]
    
    # else fuzzing data
    length = get_bytesize(field)
    return int.from_bytes(get_bytes(length), "big")


SYN = 0x2
SYN_ACK = 0x12
ACK = 0x10
FIN = 0x1
TCP_DEFAULT_MTU = 100
def tcp_handle_flags(field: dict, layer: dict, upper_layer: dict, get_bytes: types.FunctionType) -> int:
    """
    Extract current TCP flags and set them to the next correct state
    """
    return_val = 0
    if VALUE in field:
        # Apriori value can be used to make us start  on SYN_ACK instead of SYN; i.e., if  we try to interact w/ a client
        return_val = field.pop(VALUE)
    elif STREAM_DATA not in field:
        return_val = SYN
    
    if not return_val:
        last_msg = int(field[STREAM_DATA],2)
    
        # we need to rely on some simplifications; however, we could use fuzzing input to decide on potential state changes
        if last_msg == SYN:
            return_val = ACK
        elif last_msg == SYN_ACK:
            return_val = ACK
        elif last_msg == ACK:
            return_val = ACK
        else:
            return_val = FIN

    if return_val == SYN_ACK:
        layer[META][HANDSHAKE] = 0 # If we are the server we are done with the handshake :-)

    if return_val in [SYN_ACK, ACK] and layer[BODY][SIZE] == 0:
        layer[BODY][SIZE] = TCP_DEFAULT_MTU
    return return_val


# DHCP
MAGIC = 0x63825363
STATE_INIT = 1
STATE_OFFER_SENT = 2
def dhcp_handle_options(field: dict, layer: dict, upper_layer: dict, get_bytes: types.FunctionType) -> int:
    """
    Assemble a valid dhcp options payload, which allows to emulate a valid dhcp server.
    dhcp payloads are composed of <type><length><value> fields. Hence it is easier to use a handler instead
    of static or fuzzed values.
    """
    if VALUE in layer[HEADER]['op'] and layer[HEADER]['op'][VALUE] == 1:
        # We were set to operate as a client!
        pass

    # state can either be STATE_INIT or STATE_OFFER_SENT; 
    state = STATE_INIT
    if STREAM_DATA in field:
        # if last message was init move to offer sent; else basically reset to init
        if int(field[STREAM_DATA][32:56], 2) == 0x350102:
            state = STATE_OFFER_SENT

    siaddr =  int(layer[HEADER]['siaddr'][STREAM_DATA], 2)
    payload = MAGIC
    if state == STATE_INIT:
        # DHCP OFFER
        payload <<= 3 * 8
        payload |= 0x350102

        # DEFAULT VAL subnet mask 255.255.255.0
        payload <<= 6 * 8
        payload |= 0x0104ffffff00

        # dhcp server siaddr
        payload <<= 2 * 8
        payload |= 0x3604
        payload <<= 4 * 8
        payload |= siaddr

    elif state == STATE_OFFER_SENT:
        # DHCP ACK
        payload <<= 3 * 8
        payload |= 0x350105

        # DEFAULT VAL subnet mask 255.255.255.0
        payload <<= 6 * 8
        payload |= 0x0104ffffff00

        # dhcp server self._server_ip
        payload <<= 2 * 8
        payload |= 0x3604
        payload <<= 4 * 8
        payload |= siaddr

    payload <<= 8
    payload |= 0xff
    
    # manually 'resize' the header; as the options field has a size of 0 in the config, we need to resize it to its current length
    layer[META][HEADER_LEN] -= field[STREAM_LEN]
    set_field_size(field, layer, len(f"{payload:0x}") // 2)
    layer[META][HEADER_LEN] += field[STREAM_LEN]
    
    return payload


# icmp6
def icmp6_body_handler(field: dict, layer: dict, upper_layer: dict, get_bytes: types.FunctionType) -> int:
    # just a dummy so far
    set_field_size(field, layer, 8)
    return 0xffffffffffffffff


def ble_handle_llid(field: dict, layer: dict, upper_layer: dict, get_bytes: types.FunctionType) -> int:
    """ Handle BLE LLID """
    # currently just return random val
    return int.from_bytes(get_bytes(1), "big") & 0x3


extended_header_fields = ['extended_header_flags', 'AdvA', 'TargetA', 'CTEInfo', 'AdvDataInfo', 'AuxPtr', 'SyncInfo', 'TxPower', 'ACAD']
def ble_ext_header_length_handler(field: dict, layer: dict, upper_layer: dict, get_bytes: types.FunctionType) -> int:
    """
    Calculated the added length of the extended header fields, that are in use
    """
    length = 0
    for ext_field in extended_header_fields:
        if ext_field not in layer[HEADER]:
            continue
        
        if C_MASKED in layer[HEADER][ext_field] and layer[HEADER][ext_field][C_MASKED]:
            continue
        length += layer[HEADER][ext_field][SIZE]

    return length
    
#####################
# Condition handler #
#####################

def condition_handler(field: dict, layer: dict, upper_layer: dict, get_bytes: types.FunctionType) -> int:
    """
    Small handler showing the interface for implmenting handlers used by conditional fields.

    Args:
        field: dictionary of the field the handler function is executed from
        layer: the entire current layer of the packet (which contains the field)
        uppper_layer: the next upper layer; i.e., the layer assembled previous to the current on
        get_bytes: Callback to access fuzzer bytes

    Returns:
        1 if the condition is satisified; i.e., the field exists
        0 if the condition is not satisfied
    """

    return 1

def extended_header_flags_handler(field: dict, layer: dict, upper_layer: dict, get_bytes: types.FunctionType):
    """ BLE handler to decide which extended header fields to use """
    # first set adv mode
    advMode = int.from_bytes(get_bytes(1), "big")
    layer[HEADER]['advMode'][VALUE] = advMode
    layer[HEADER]['advMode'][C_MASKED] = False

    
    if resolve_protocol_id(layer[META][ID]) == "BLE_adv_ADV_EXT_IND":
        return adv_ext_header(field, layer, get_bytes)
    if resolve_protocol_id(layer[META][ID]) == "BLE_adv_AUX_ADV_IND":
        return aux_adv_header(field, layer, get_bytes)
    if resolve_protocol_id(layer[META][ID]) == "BLE_adv_AUX_SYNC_IND":
        return aux_sync_header(field, layer, get_bytes)


# bitmask order: [AdvA, TargetA, CTEINFO, ADI, Aux Ptr, Sync Info, Tx Power, ACAD, AdvData]
def aux_sync_header(field: dict, layer: dict, get_bytes: types.FunctionType) -> int:
    """ BLE use the Aux Sync header """
    flag = 0    
    advMode = layer[HEADER]['advMode'][VALUE]  
    if advMode & 3 == 0:
        flag = 0b00111011
    
    return flag

def adv_ext_header(field: dict, layer: dict, get_bytes: types.FunctionType) -> int:
    """ use the adv extended header """
    # core5.3 p 2682 (2.3.1.5 ADV_EXT_IND)
    flag = 0    
    advMode = layer[HEADER]['advMode'][VALUE]  
    if advMode & 3 == 0:
        if advMode >> 6 == 0:   
            flag = 0b10000010
        elif advMode >> 6 == 1:   
            flag = 0b10011010
        elif advMode >> 6 == 2:   
            flag = 0b11000010
        elif advMode >> 6 == 3:   
            flag = 0b11011010
    if advMode & 3== 1:
        if advMode >> 7:   
            flag = 0b00011010
        else:
            flag = 0b00011010
        
    if advMode & 3 == 2:
        if advMode >> 7:   
            flag = 0b00011010
        else:
            flag = 0b00011010
    
    return flag

def aux_adv_header(field: dict, layer: dict, get_bytes: types.FunctionType) -> int:
    """ USe the aux adv header """
    flag = 0 # bitmask which encodes whether a field is used; always use optional fields
    advMode = layer[HEADER]['advMode'][VALUE]  
    if advMode & 3 == 0:
        if advMode >> 7:        
            # non-connectable, non-scannable, undirected
            flag = 0b10011111
        else:
            # non-conectable, non-scannable, directed
            flag = 0b11011111

    if advMode & 3 == 1:
        if advMode >> 7:        
            # connectable, undirected
            flag = 0b10010011
        else:
            # conectable, directed
            flag = 0b11010011
        pass
    if advMode & 3 == 2:
        if advMode >> 7:        
            # scannable undirected
            flag = 0b10010011
        else:
            # scannable, directed
            flag = 0b11010011
        pass

    return flag
    

def ieee802154_generic_fcf(field: dict, layer: dict, fcf: int):
    """ Based on a given fcf modify the rest of the packet.
        Depending on the fcf addresses and PANs are shortened or omitted.
    """
    source_addr_mode = fcf >> 14
    frame_version = (fcf >> 12) & 3
    dest_addr_mode = (fcf >> 10) & 3
    pan_id_compr = (fcf >> 6) & 1
    ack_request = (fcf >> 5) & 1
    frame_pending = (fcf >> 4) & 1
    sec_enabled = (fcf >> 3) & 1
    frame_type = fcf & 7

    header = layer[HEADER]
    set_field_info(header['destination_PAN'], C_MASKED, True)  
    set_field_info(header['destination_addr'], C_MASKED, True)  
    set_field_info(header['source_PAN'], C_MASKED, True)  
    set_field_info(header['source_addr'], C_MASKED, True)  
    set_field_info(header['auxillary_security_header'], C_MASKED, True)  

    if sec_enabled == 1 and frame_version > 0:
        # TODO need auxillary header
        pass
   
    if dest_addr_mode == 0:
        pass
    if dest_addr_mode == 1:
        fcf = (fcf & 0xf3ff)
        dest_addr_mode = 0
    if dest_addr_mode == 2:
        set_field_info(header['destination_addr'], C_MASKED, False)  
        set_header_field_size(layer, 'destination_addr', 2)
    if dest_addr_mode == 3:
        set_field_info(header['destination_addr'], C_MASKED, False)  
        set_header_field_size(layer, 'destination_addr', 8)
        pass

    if source_addr_mode == 0:
        pass
    if source_addr_mode == 1:
        fcf = (fcf & 0x3fff) | 0x8000
        source_addr_mode = 2
    if source_addr_mode == 2:
        set_field_info(header['source_addr'], C_MASKED, False)
        set_header_field_size(layer, 'source_addr', 2)
        pass
    if source_addr_mode == 3:
        set_field_info(header['source_addr'], C_MASKED, False)  
        set_header_field_size(layer, 'source_addr', 8)

    if pan_id_compr == 0:
        if dest_addr_mode > 0:
            set_header_field_size(layer, 'destination_PAN', 2)
            set_field_info(header['destination_PAN'], C_MASKED, False)
        if source_addr_mode > 0:
            set_header_field_size(layer, 'source_PAN', 2)
            set_field_info(header['source_PAN'], C_MASKED, False)  

    if pan_id_compr == 1:
        if source_addr_mode > 1:# and dest_addr_mode > 1:
            set_header_field_size(layer, 'destination_PAN', 2)
            set_field_info(header['destination_PAN'], C_MASKED, False)
        
    if not VALUE in header["destination_PAN"]:
        set_field_info(header['destination_PAN'], VALUE, 0xffff) 
    if not VALUE in header["destination_addr"]:
        if SIZE in header["destination_addr"] and header["destination_addr"][SIZE] == 2:
            set_field_info(header['destination_addr'], VALUE, 0xffff) 
        else:
            set_field_info(header['destination_addr'], VALUE, 0xffffffffffffffff) 

    if field[VALUE] != fcf:
        # this can be the case if we already sent previous packets
        field[VALUE] = fcf
        field[STREAM_LEN] = get_bitsize(field)
        swapped_endianess = (fcf & 0xff) << 8 | (fcf >> 8) &0xff
        field[STREAM_DATA] = f"{be_place_data(swapped_endianess, field[STREAM_LEN]):0{field[STREAM_LEN]}b}"[-field[STREAM_LEN]:]

    return


def ieee802154_mac_data_fcf(field: dict, layer: dict, upper_layer: dict, get_bytes: types.FunctionType) -> int:
    """ 
    Set the Frame control field and mask/unmask the fields depending on the FCF
    """
    if VALUE in field:
        fcf = field[VALUE]
    else:
        fcf = int.from_bytes(get_bytes(2), "big")
        frame_type = IEEE802154_DATA
        fcf  = (fcf & 0xfff8) | frame_type
        fcf = fcf & 0xfeff # zero out a reserved bit

        field[VALUE] = fcf
        field[STREAM_LEN] = get_bitsize(field)
        swapped_endianess = (fcf & 0xff) << 8 | (fcf >> 8) &0xff
        field[STREAM_DATA] = f"{be_place_data(swapped_endianess, field[STREAM_LEN]):0{field[STREAM_LEN]}b}"[-field[STREAM_LEN]:]

    ieee802154_generic_fcf(field, layer, fcf)
    return 1


def ieee802154_mac_beacon_fcf(field: dict, layer: dict, upper_layer: dict, get_bytes: types.FunctionType) -> int:
    """ 
    Set the Frame control field and mask/unmask the fields depending on the FCF
    """
    if VALUE in field:
        fcf = field[VALUE]
    else:
        fcf = int.from_bytes(get_bytes(2), "big")
        frame_type = IEEE802154_BEACON
        fcf  = (fcf & 0xfff8) | frame_type 

        field[VALUE] = fcf
        field[STREAM_LEN] = get_bitsize(field)
        swapped_endianess = (fcf & 0xff) << 8 | (fcf >> 8) &0xff
        field[STREAM_DATA] = f"{be_place_data(swapped_endianess, field[STREAM_LEN]):0{field[STREAM_LEN]}b}"[-field[STREAM_LEN]:]

    ieee802154_generic_fcf(field, layer, fcf)
    return 1


def ieee802154_mac_command_fcf(field: dict, layer: dict, upper_layer: dict, get_bytes: types.FunctionType) -> int:
    """ 
    Set the Frame control field and mask/unmask the fields depending on the FCF
    """
    if VALUE in field:
        fcf = field[VALUE]
    else:
        fcf = int.from_bytes(get_bytes(2), "big")
        frame_type = IEEE802154_COMMAND
        fcf  = (fcf & 0xfff8) | frame_type

        field[VALUE] = fcf
        field[STREAM_LEN] = get_bitsize(field)
        swapped_endianess = (fcf & 0xff) << 8 | (fcf >> 8) &0xff
        field[STREAM_DATA] = f"{be_place_data(swapped_endianess, field[STREAM_LEN]):0{field[STREAM_LEN]}b}"[-field[STREAM_LEN]:]

    ieee802154_generic_fcf(field, layer, fcf)
    return 1


def sixlowpan_mesh_handler(field: dict, layer: dict, upper_layer: dict, get_bytes: types.FunctionType) -> int:
    """ Handling for the 6LoWPAN mesh header """
    field[C_MASKED] = True
    set_field_size(field, layer, 0)
    field[META][HEADER_LEN] = 0
    return 0


FRAG_THRESHOLD = 110 # size where we start fragemnting packets
def sixlowpan_fragmentation_handler(field: dict, layer: dict, upper_layer: dict, get_bytes: types.FunctionType) -> int:
    """ Handling for the 6LoWPAN fragmentation header """
    if upper_layer:
        body_len = len(upper_layer[PKT]) // 8  
    else:
        body_len = layer[BODY][SIZE]

    if body_len < FRAG_THRESHOLD:
        # No fragmentation needed
        field[C_MASKED] = True
        return 0 #easy

    field[C_MASKED] = False
    total_frags = -((-1 * body_len) // FRAG_THRESHOLD)

    if FRAGMENT_NR in layer[META] and layer[META][FRAGMENT_NR] != 0:
        # FRAG N
        field[HEADER]['pattern'][VALUE] = 0b11100
    else:
        # FRAG 0
        field[HEADER]['pattern'][VALUE] = 0b11000
        layer[META][FRAGMENT_NR] = 0

    field[HEADER]['pattern'][TYPE] = T_DATA

    # datagram_size
    field[HEADER]['datagram_size'][VALUE] = body_len
    field[HEADER]['datagram_size'][TYPE] = T_DATA

    # datagram_tag stays be fuzzed
    # datagram_offset 
    if field[HEADER]['pattern'][VALUE] == 0b11100:
        field[HEADER]['datagram_offset'][C_MASKED] = False
        if VALUE in field[HEADER]['datagram_offset']:
            field[HEADER]['datagram_offset'][VALUE] = field[HEADER]['datagram_offset'][VALUE] + FRAG_THRESHOLD
        field[HEADER]['datagram_offset'][TYPE] = T_DATA
    else:
        field[HEADER]['datagram_offset'][C_MASKED] = True
        field[HEADER]['datagram_offset'][VALUE] = 0

    return FRAG_THRESHOLD * 8

def sixlowpan_compression_handler(field: dict, layer: dict, upper_layer: dict, get_bytes: types.FunctionType) -> int:
    """ Handling for the 'regular' 6LoWPAN compression header (LOWPAN HC1 compression) """
    ip6_layer = layer[HEADER]['ip6_header']
    if not META in ip6_layer or resolve_protocol_id(ip6_layer[META][ID]) != '6lowpan_IP6': # ipv6 
         field[C_MASKED] = True
         return 0
    field[C_MASKED] = False

    # full compression
    field[HEADER]['pattern'][VALUE] = 0x42
    field[HEADER]['pattern'][TYPE] = T_DATA
    set_header_field_size(field, 'pattern', 1)
    encoding = 0b11111000

    if resolve_protocol_id(int(ip6_layer[HEADER]['next_header'][STREAM_DATA], 2)) == "UDP":
        encoding |= (0b01 << 1)
    if resolve_protocol_id(int(ip6_layer[HEADER]['next_header'][STREAM_DATA], 2)) == "TCP":
        encoding |= (0b11 << 1)
    if resolve_protocol_id(int(ip6_layer[HEADER]['next_header'][STREAM_DATA], 2)) == "ICMP6":
        encoding |= (0b10 << 1)
    
    # TODO allow for partial encoding based on fuzzing byte
    ip6_layer[HEADER]['source_addr'][COMPRESSED] = True
    ip6_layer[HEADER]['version'][COMPRESSED] = True
    ip6_layer[HEADER]['payload_len'][COMPRESSED] = True
    ip6_layer[HEADER]['destination_addr'][COMPRESSED] = True
    ip6_layer[HEADER]['flow_label'][COMPRESSED] = True
    ip6_layer[HEADER]['traffic_class_ds'][COMPRESSED] = True
    ip6_layer[HEADER]['traffic_class_ecn'][COMPRESSED] = True
    ip6_layer[HEADER]['next_header'][COMPRESSED] = True

    field[HEADER]['encoding'][VALUE] = encoding
    field[HEADER]['encoding'][TYPE] = T_DATA
    set_header_field_size(field, 'encoding', 1)

    return 1


def sixlowpan_iphc_compression_handler(field: dict, layer: dict, upper_layer: dict, get_bytes: types.FunctionType) -> int:
    """ HAndle LoWPAN IPHC compression """
    ip6_layer = layer[HEADER]['ip6_header']
    if not META in ip6_layer or resolve_protocol_id(ip6_layer[META][ID]) != '6lowpan_IP6': # ipv6 
         field[C_MASKED] = True
         return 0

    field[C_MASKED] = False
    field[HEADER]['pattern'][VALUE] = 0x3
    field[HEADER]['pattern'][TYPE] = T_DATA
    set_header_field_size(field, 'pattern', 'b3')

    encoding = int.from_bytes(get_bytes(2), "big") & 0x1fff
    # always compress:
    set_header_field(ip6_layer, 'version', COMPRESSED, True) 
    set_header_field(ip6_layer, 'payload_len', COMPRESSED, True) 

    # TF
    if (encoding >> 11) == 0b11:
        set_header_field(ip6_layer, 'flow_label', COMPRESSED, True) 
        set_header_field(ip6_layer, 'traffic_class_ds', COMPRESSED, True) 
        set_header_field(ip6_layer, 'traffic_class_ecn', COMPRESSED, True)
        set_header_field_size(ip6_layer, 'compression_padding', 0)

    if (encoding >> 11) == 0b10:
        set_header_field(ip6_layer, 'flow_label', COMPRESSED, True) 
        set_header_field_size(ip6_layer, 'compression_padding', 0)

    if (encoding >> 11) == 0b01:
        set_header_field(ip6_layer, 'traffic_class_ds', COMPRESSED, True)
        set_header_field_size(ip6_layer, 'compression_padding', 'b2')
        set_header_field(ip6_layer, 'compression_padding', STREAM_DATA, '00') 

    if (encoding >> 11) == 0:
        set_header_field_size(ip6_layer, 'compression_padding', 'b4')
        #set_header_field(ip6_layer, 'compression_padding', SIZE, 'b4') 
        set_header_field(ip6_layer, 'compression_padding', STREAM_DATA, '0000') 

    # NH
    use_nhc = False
    if (encoding >> 10) & 1:
        #TODO we need to compress the previous header as well, therefore skip this for now
        use_nhc = True
        set_header_field(ip6_layer, 'next_header', COMPRESSED, True) 
        # subsequently we need to compress the next header as well
    
    #hlim 
    encoding &= 0b1110011111111
    if get_header_field(ip6_layer, 'hop_limit', VALUE) == 1:
        set_header_field(ip6_layer, 'hop_limit', COMPRESSED, True) 
        encoding |= 0b0000100000000

    elif get_header_field(ip6_layer, 'hop_limit', VALUE) == 64:
        set_header_field(ip6_layer, 'hop_limit', COMPRESSED, True) 
        encoding |= 0b0001000000000

    elif get_header_field(ip6_layer, 'hop_limit', VALUE) == 255:
        set_header_field(ip6_layer, 'hop_limit', COMPRESSED, True) 
        encoding |= 0b0001100000000

    # cid
    if (encoding >> 7) & 1:
        set_header_field_size(field, 'cid', 1)
    else:
        set_header_field_size(field, 'cid', 0)

    # sac
    if (encoding >> 6) & 1 == 0:
        # sam case 1
        if (encoding >> 4) & 3 == 0:
            pass # no compression

        if (encoding >> 4) & 3 == 0b01:
            set_header_field_size(ip6_layer, 'source_addr', 8)

        if (encoding >> 4) & 3 == 0b10:
            set_header_field_size(ip6_layer, 'source_addr', 2)

        if (encoding >> 4) & 3 == 0b11:
            set_header_field(ip6_layer, 'source_addr', COMPRESSED, True)  # full compression

    else:
        # sam case 2
        if (encoding >> 4) & 3 == 0:
            set_header_field_size(ip6_layer, 'source_addr', 0)
            set_header_field(ip6_layer, 'source_addr', VALUE, 0x0)  # unspecified address

        if (encoding >> 4) & 3 == 0b01:
            set_header_field_size(ip6_layer, 'source_addr', 8)

        if (encoding >> 4) & 3 == 0b10:
            set_header_field_size(ip6_layer, 'source_addr', 2)

        if (encoding >> 4) & 3 == 0b11:
            set_header_field(ip6_layer, 'source_addr', COMPRESSED, True)  # full compression

    # multicast
    if (encoding >> 3) & 1 == 0:
        # dac
        if (encoding >> 2) & 1 == 0:
            # dam case 1
            if encoding & 3 == 0:
                pass # no compression
            if encoding & 3 == 0b01:
                set_header_field_size(ip6_layer, 'destination_addr', 8)
            if encoding & 3 == 0b10:
                set_header_field_size(ip6_layer, 'destination_addr', 8)
            if encoding & 3 == 0b11:
                set_header_field(ip6_layer, 'destination_addr', COMPRESSED, True)  # full compression
        else:
            # dam case 2
            if encoding & 3 == 0:
                pass
                #print("Reached illegal compression state! Are you sure everything is correct? (2)")
            if encoding & 3 == 0b01:
                set_header_field_size(ip6_layer, 'destination_addr', 8)
            if encoding & 3 == 0b10:
                set_header_field_size(ip6_layer, 'destination_addr', 2)
            if encoding & 3 == 0b11:
                set_header_field(ip6_layer, 'destination_addr', COMPRESSED, True)  # full compression
    else:
        # dac
        if (encoding >> 2) & 1 == 0:
            # dam case 3
            if encoding & 3 == 0:
                pass # no compression
            if encoding & 3 == 0b01:
                set_header_field_size(ip6_layer, 'destination_addr', 6)
            if encoding & 3 == 0b10:
                set_header_field_size(ip6_layer, 'destination_addr', 4)
            if encoding & 3 == 0b11:
                set_header_field_size(ip6_layer, 'destination_addr', 1)

        else:
            # dam case 4
            if encoding & 3 == 0:
                set_header_field_size(ip6_layer, 'destination_addr', 6)
            else:
                pass
                #print("Reached illegal compression state! Are you sure everything is correct? (3)")


    # as we use iphc, we also unmask the first nhc handlers
    if use_nhc:
        # we only use udp_nhc if either no handlers are unmasked or exactly one is used
        nhcs = 0
        for name, header_field in layer[HEADER].items():
            if nhcs > 0:
                # we only use
                nhcs += 1
                continue
            if name == 'ip6_header' or header_field[TYPE] != T_NESTED or ACTION in header_field:
                continue
            if C_MASKED in header_field and header_field[C_MASKED]:
                continue
            #print(f"unmasking {name}_nhc")
            layer[HEADER][f"{name}_nhc"][C_MASKED] = False
            nhcs += 1
            continue
        if nhcs < 2:
            udp_nhc = sixlowpan_nhc_handler(None, layer, upper_layer, get_bytes)

    field[HEADER]['encoding'][TYPE] = T_DATA
    set_header_field_size(field, 'encoding', 'b13')
    field[HEADER]['encoding'][VALUE] = encoding

    return 1


def sixlowpan_nhc_handler(field: dict, layer: dict, upper_layer: dict, get_bytes: types.FunctionType) -> int: 
    """ LoWPAN Next HEader Compression for UDP """
    if layer[META][ID] == 0x086dd:
        ip6_layer = layer
    elif 'ip6_header' in layer[HEADER]:
        ip6_layer = layer[HEADER]['ip6_header']
    if not upper_layer:
        return 0
    if resolve_protocol_id(upper_layer[META][ID]) != 'UDP': 
        # TODO: we can add extension header like 
        # 1110000N: IPv6 Hop-by-Hop Options Header       [RFC6282]
        # 1110001N: IPv6 Routing Header                  [RFC6282]
        # 1110010N: IPv6 Fragment Header                 [RFC6282]
        # 1110011N: IPv6 Destination Options Header      [RFC6282]
        # 1110100N: IPv6 Mobility Header                 [RFC6282]
        return 0

    udp_packet = layer[BODY][STREAM_DATA]
    if len(udp_packet) < 64:
        # No need for compression
        return 0

    udp_header = udp_packet[:8*8]
    udp_body = udp_packet[8*8:]
    source = udp_header[:2*8] 
    dest = udp_header[2*8:4*8]
    length = udp_header[4*8:6*8] 
    checksum = udp_header[6*8:]

    compression = "11110" #prefix

    # checksum eliding based on packet
    elide_checksum = False
    if (int(source, 2) ^ int(dest, 2) ^ int(length, 2) ^ int(checksum, 2)) % 1:
        compression += "1"
        elide_checksum = True
    else:
        compression += "0"

    elide_source = False
    elide_dest = False
    elide_both = False
    if int(source, 2) >> 4 == 0xf0b and int(dest, 2) >> 4 == 0xf0b:
        elide_both = True

    if int(source, 2) >> 8 == 0xf0:
        elide_source = True
    if int(dest, 2) >> 8 == 0xf0: 
        elide_dest = True

    if elide_both:
        compression += f"11{source[-4:]}{dest[-4:]}"
    elif elide_source:
        compression += f"10{source[-8:]}{dest}"
    elif elide_dest:
        compression += f"01{source}{dest[-8:]}"     
    else:
        compression += f"00{source}{dest}"
        
    if not elide_checksum:
        compression += checksum

    layer[BODY][STREAM_DATA] = compression + udp_body
    layer[BODY][SIZE] = (len(compression) + len(udp_body)) // 8
    layer[META]['dirty'] = 1

    return 1

compression_handler = [sixlowpan_compression_handler, sixlowpan_iphc_compression_handler, None]
def sixlowpan_compression_wrapper(field: dict, layer: dict, upper_layer: dict, get_bytes: types.FunctionType) -> int:
    """ Wrapper that user fuzzer input to decide which 6LoWPAN compression to use """
    handler = compression_handler[int.from_bytes(get_bytes(1), "big") % len(compression_handler)]
    if handler == None:
        field[HEADER]['pattern'][VALUE] = 0b01000001 
        set_header_field_size(field, 'pattern', 1)
        field[HEADER]['pattern'][TYPE] = T_DATA 
        set_header_field_size(field, 'encoding', 0)
        return 0

    return handler(field, layer, upper_layer, get_bytes)





def ip6_ext_hdr_roll(field: dict, layer: dict, upper_layer: dict, get_bytes: types.FunctionType) -> int:
    """ Decide on IPv6 Extension headers to use
      0: IPv6 Hop-by-Hop Options Header [RFC2460]
      1: IPv6 Routing Header [RFC2460]
      2: IPv6 Fragment Header [RFC2460]
      3: IPv6 Destination Options Header [RFC2460]
      4: IPv6 Mobility Header [RFC6275]
    """
    ext_header = ['ext_header_hop', 'ext_header_routing', 'ext_header_frag', 'ext_header_dest_options', 'ext_header_mobility']
    dice = int.from_bytes(get_bytes(1), "big") % ((1 << len(ext_header) + 1) - 1)
    used_headers = []
    unused_headers = []
    # Use fuzzer byte as a mask that decides which headers to use
    for i in range(len(ext_header)):
        if dice & (1 << i):
            used_headers.append(ext_header[i])
        else:
            unused_headers.append(ext_header[i])

    for header in ext_header:
        if header in unused_headers:
            layer[HEADER][header][C_MASKED] = True
        if f"{header}_nhc" in layer[HEADER]:
            # Depending wether we are in 6lowpan ipv6 or regular ipv6
            layer[HEADER][f"{header}_nhc"][C_MASKED] = True

    used_headers = ['ip6_header'] + used_headers
    for i in range(len(used_headers) - 1):
        header_name = used_headers[i]
        next_header_name = used_headers[i + 1]
        field = layer[HEADER][header_name][HEADER]['next_header']
        field[TYPE] = T_DATA
        field[VALUE] = layer[HEADER][next_header_name][META][ID]

    return 1

    
def nhc_compression_handler(field: dict, layer: dict, upper_layer: dict, get_bytes: types.FunctionType) -> int:
    """ Handling for nhc (next header compression) """
    target = field['target']
    nested_header = layer[HEADER][target][HEADER]

    compressed_field = layer[HEADER][target][META][ID]
    if compressed_field == 0:
        field[HEADER]['eid'][VALUE] = 0
    elif compressed_field == 43:
        field[HEADER]['eid'][VALUE] = 1
    elif compressed_field == 44:
        field[HEADER]['eid'][VALUE] = 2
    elif compressed_field == 60:
        field[HEADER]['eid'][VALUE] = 3
    elif compressed_field == 135:
        field[HEADER]['eid'][VALUE] = 4
    field[HEADER]['eid'][TYPE] = T_DATA
    #
    # TODO for now only elide when next header is udp nhc
    if nested_header['next_header'][VALUE] == 0x11:
        field[HEADER]['nh'][VALUE] = 1
        nested_header['next_header'][COMPRESSED] = True
    else:
        field[HEADER]['nh'][VALUE] = 0
    field[HEADER]['nh'][TYPE] = T_DATA

    # set length of field, from 8 octets to octets
    if 'header_ext_length' in nested_header:
        len_field = nested_header['header_ext_length']
        len_field[VALUE] = 8 + len_field[VALUE] * 8
        len_field[STREAM_DATA] = f"{len_field[VALUE]:0{len_field[STREAM_LEN]}b}"[-len_field[STREAM_LEN]:]

    # add padding
    nested_length = (sum([get_bitsize(f) for x,f in nested_header.items()]) // 8) -2
    set_field_size(nested_header['compression_padding'], layer[HEADER][target], 8 - nested_length % 8 if nested_length % 8 else 0)
    #ested_header['compression_padding'][STREAM_LEN] = get_bitsize(nested_header['compression_padding'])
    nested_header['compression_padding'][STREAM_DATA] =  nested_header['compression_padding'][STREAM_LEN] * '0'


def ip6_ext_ptr(field: dict, layer: dict, upper_layer: dict, get_bytes: types.FunctionType) -> int:
    """ Set the pointer chain for the used headers so header1->header2->...->upper_layer_header """
    # first get used headers
    used_headers = list()
    for nested, field in layer[HEADER].items():
        if field[TYPE] != T_NESTED:
            continue
        if C_MASKED in field and field[C_MASKED] == True:
            continue
        if ACTION in field:
            continue
        used_headers.append(nested)

    if len(used_headers) == 1:
        return 0
    
    for i in range(len(used_headers) - 1):
        header_name = used_headers[i]
        next_header_name = used_headers[i + 1]
        field = layer[HEADER][header_name][HEADER]['next_header']
        field[TYPE] = T_DATA
        field[VALUE] = layer[HEADER][next_header_name][META][ID]

    return 0


def ip6_total_len_handler(field: dict, layer: dict, upper_layer: dict, get_bytes: types.FunctionType) -> int:
    """ Handler to update the length field based on the used extension headers """
    ip6_header = layer[HEADER]['ip6_header'][HEADER]
    len_field = ip6_header['payload_len']

    used_headers = list()
    for nested, field in layer[HEADER].items():
        if field[TYPE] != T_NESTED:
            continue
        if C_MASKED in field and field[C_MASKED] == True:
            continue
        if ACTION in field:
            continue
        if nested == 'ip6_header':
            continue
        used_headers.append(nested)

    updated_len = len_field[VALUE]
    for header_name in used_headers:
        header_len = layer[HEADER][header_name][META][HEADER_LEN]
        updated_len += header_len // 8

    len_field[VALUE] = updated_len
    len_field[STREAM_DATA] = f"{len_field[VALUE]:0{len_field[STREAM_LEN]}b}"[-len_field[STREAM_LEN]:]
    return 0


# IP4
MTU = 1500
# Fragments are specified as multiples of 8! TODO
def ip4_fragmentation_handler(field: dict, layer: dict, upper_layer: dict, get_bytes: types.FunctionType) -> int:
    """
    Perform IPv4 fragmentation if need be; called for the fragment offset field
    """
    # we need to assume an mtu
    set_header_field(layer, 'fragment_offset', VALUE, 0)
    if MTU < (len(layer[BODY][STREAM_DATA]) // 8):
        # fragmentation necessary   
        # check if we are in the first or subsequent packets
        if FRAGMENT_NR in layer[META] and layer[META][FRAGMENT_NR] != 0:
            # subsequent fragment (or last)
            set_header_field(layer, 'fragment_offset', VALUE, layer[META][FRAGMENT_NR] * MTU) 
            # check if it is the last fragment
            if (get_header_field(layer, 'fragment_offset', VALUE) + MTU) > (len(upper_layer[PKT]) // 8):
                # last fragment
                set_header_field(layer, 'flags', VALUE, 0) 
            else:
                set_header_field(layer, 'flags', VALUE, 0b001) 
            
        else:
            # first fragment; keep offset to 0
            set_header_field(layer, 'flags', VALUE, 0b001) 
            set_field_type(layer[HEADER]['flags'], T_DATA)
            # need to put it in place immediately, otherwise it will be overwritten (only first time)
            set_header_field(layer, 'flags', STREAM_LEN, get_bitsize(layer[HEADER]['flags']))
            set_header_field(layer, 'flags', STREAM_DATA, f"{layer[HEADER]['flags'][VALUE]:0{layer[HEADER]['flags'][STREAM_LEN]}b}"[-layer[HEADER]['flags'][STREAM_LEN]:])
    
    else:
        set_header_field(layer, 'flags', VALUE, 0b010) #dont fragment 
        set_field_type(layer[HEADER]['flags'], T_DATA)
        set_header_field(layer, 'flags', STREAM_LEN, get_bitsize(layer[HEADER]['flags']))
        set_header_field(layer, 'flags', STREAM_DATA, f"{layer[HEADER]['flags'][VALUE]:0{layer[HEADER]['flags'][STREAM_LEN]}b}"[-layer[HEADER]['flags'][STREAM_LEN]:])

    set_header_field(layer, 'fragment_offset', STREAM_LEN, get_bitsize(field))
    set_header_field(layer, 'fragment_offset', STREAM_DATA, f"{field[VALUE]:0{field[STREAM_LEN]}b}"[-field[STREAM_LEN]:])
    layer[META]['dirty'] = 1

    return MTU * 8


def modbus_data(field: dict, layer: dict, upper_layer: dict, get_bytes: types.FunctionType) -> int:
    """ Handler for the modbus payload """
    size = int.from_bytes(get_bytes(1), "big") &0x7f
    if size < 4:
        size = 4
    if size > 120:
        size= 120
    field[SIZE] = size
    field[STREAM_LEN] = get_bitsize(field)
    val = int.from_bytes(get_bytes(size), "big")
    field[VALUE] = val
    return val
