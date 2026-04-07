from .utils import *

# Decide if and how to respond to messages
def check_response(protocols: list) -> (bool, list):
    """
    Return true if the packet composed of :protocols: needs a response.
    If the response needs to be different from the packet, changed the protocols lis
    """
    response = list(protocols)
    # Check for TCPIP
    if response[0] == "Ethernet":
        return True, response
    
    # Check for BLE
    if response[0] == "BLE_PHY":
        # no answer needed for advertisments
        if response[-1] in ['BLE_adv_ADV_IND', 'BLE_adv_ADV_DIRECT_IND', 'BLE_adv_ADV_NONCONN_IND',
                             'BLE_adv_ADV_SCAN_IND', 'BLE_adv_ADV_EXT_IND', 'BLE_adv_AUX_ADV_IND',
                             'BLE_adv_AUX_SYNC_IND', 'BLE_adv_AUX_CHAIN_IND']:
            return False, response
        
        # send appropriate responses to requests
        elif response[-1] == 'BLE_adv_SCAN_REQ':
            response[-1] = 'BLE_adv_SCAN_RSP'
        
        elif response[-1] == 'BLE_adv_AUX_SCAN_REQ':
            response[-1] = 'BLE_adv_AUX_SCAN_RSP'

        elif response[-1] == 'BLE_adv_AUX_CONNECT_REQ':
            response[-1] = 'BLE_adv_AUX_CONNECT_RSP'

        return True, response
    
    # Check for IEEE802154
    if response[0] == "IEEE802154_PHY":
        if response[-1] == '6lowpan_MAC_Ack':
            return False, response
        elif response[-1] in ['6lowpan_MAC_Beacon', '6lowpan_MAC_Data']:
            response[-1] = '6lowpan_MAC_Ack'
        
        return True, response
    
    return False, response


# extraction parsers
def sample_parser(header: dict, payload: bytes) -> dict:
    """
    This function shows the parameters of the individual layer parsers. 

    Arguments:
        header: dictionary, containing the header fields of the layer
        payload: the included payload (i.e., upper layers or smth else)
        TODO maybe existing a priori values, that require no further parsing
    Returns:
        dictionary containing the 'pointers' to the extracted header values (as used in the apriori option) 
        and their according values.
    """

def ethernet_parser(header: dict, payload: bytes) -> dict:
    """
    Extract values and store the mac address of the firmware if it isnt zero.
    Extract the destination of the packet and store it, if it is no broadcast or zero
    """
    fw_source = header["src"][VALUE]
    fw_dest = header["dest"][VALUE]
    extracted_values = dict()
    if fw_source != 0:
        extracted_values["TCPIP.MAC_dest"] = fw_source

    if fw_dest != 0xffffffffffff and fw_dest != 0:
        extracted_values["TCPIP.MAC_source"] = fw_dest        

    return extracted_values


def arp_parser(header: dict, payload: bytes) -> dict:
    """
    Extract values and store the mac address of the firmware if it isnt zero.
    Extract the destination of the packet and store it, if it is no broadcast or zero
    """
    extracted_values = dict()
    mac_source = header["sha"][VALUE]
    mac_dest = header["tha"][VALUE]
    ip4_source = header['tpa'][VALUE]
    ip4_dest = header['spa'][VALUE]
    htype = header['htype'][VALUE]
    ptype = header['ptype'][VALUE]
    hlen = header['hlen'][VALUE]
    plen = header['plen'][VALUE]

    if mac_source != 0 :
        extracted_values["TCPIP.MAC_dest"] = mac_source

    if mac_dest != 0 and mac_source != mac_dest:
        extracted_values["TCPIP.MAC_source"] = mac_dest

    if ip4_dest != 0:
        extracted_values["TCPIP.IP4_dest"] = ip4_dest
    if ip4_source != ip4_dest:
        extracted_values["TCPIP.IP4_source"] = ip4_source
     
    extracted_values['ARP.htype'] = htype
    extracted_values['ARP.ptype'] = ptype
    extracted_values['ARP.hlen'] = hlen
    extracted_values['ARP.plen'] = plen

    return extracted_values


def ip4_parser(header: dict, payload: bytes) -> dict:
    """
    Extract values and store the ip address of the firmware if it isnt zero.
    Extract the destination ip of the packet and store it, if it is no broadcast or zero
    """
    src_ip = get_header_field(header, "source_ip", VALUE)
    dest_ip = get_header_field(header, "destination_ip", VALUE)
    extracted_values = dict()

    if src_ip != 0:
        extracted_values["TCPIP.IP4_dest"] = src_ip

    if dest_ip != 0 and dest_ip != 0xffffffff:
        extracted_values["TCPIP.IP4_source"] = dest_ip
    
    return extracted_values


def ip6_parser(header: dict, payload: bytes) -> dict:
    """ parse an IP6 packet/dict and extract source and destination """
    extracted_values = dict()
    src_ip = get_header_field(header, "source_addr", VALUE) if VALUE in header["source_addr"] else -1
    dest_ip = get_header_field(header, "destination_addr", VALUE) if VALUE in header["destination_addr"] else -1

    # uncompressed addresses?
    if get_header_field(header, "source_addr", SIZE) == 0x10 and src_ip != -1:
        extracted_values["TCPIP.IP6_dest"] = src_ip
    if get_header_field(header, "source_addr", SIZE) == 0x10 and dest_ip != -1:
        extracted_values["TCPIP.IP6_source"] = dest_ip
    
    return extracted_values

def tcp_parser(header: dict, payload: bytes) -> dict:
    """ Parse TCP and extract sqn, ack, and flags """
    extracted_values = dict()
    flags = get_header_field(header, "flags", VALUE)
    # if we received a SYN, we are the server not the client!
    if flags == 0x2: # SYN
        extracted_values['TCP.flags'] = 0x12 # Next time sent a SYN-ACK
    sent_sqn = get_header_field(header, "sqn", VALUE)
    if sent_sqn > 1: #TODO
        extracted_values['TCP.ack'] = sent_sqn
    return extracted_values


def sixlowpan_parser(header: dict, payload: bytes) -> dict:
    """ Parse a 6LoWPAN packet and extract source and destination """
    extracted_values = dict()

    if SIZE in header['compression_header'] and header['compression_header'][SIZE] > 0:
        compression_header = header['compression_header'][HEADER]
        pattern = compression_header['pattern'][VALUE]
        ip6_layer = header['ip6_header']
        if pattern == 0b011:
            # IPHC CASE
            encoding = compression_header['encoding'][VALUE]
            # sac
            if encoding >> 6 & 1 == 0:
                # sam case 1
                if encoding >> 4 & 3 == 0:
                    val = get_header_field(ip6_layer, 'source_addr', VALUE)
                    extracted_values['TCPIP.IP6_dest'] = val
                if encoding >> 4 & 3 == 0b01:
                    val = get_header_field(ip6_layer, 'source_addr', VALUE)
                    extracted_values['TCPIP.IP6_dest'] = 0xfe800000000000000000000000000000 | val
                if encoding >> 4 & 3 == 0b10:
                    val = get_header_field(ip6_layer, 'source_addr', VALUE)
                    extracted_values['TCPIP.IP6_dest'] = 0xfe800000000000000000000000000000 | 0x000000fffe000000 | (val & 0xffff)
                if encoding >> 4 & 3 == 0b11:
                    if 'IEEE802154.LL_destination' in extracted_values:
                        val = extracted_values['IEEE802154.LL_destination']
                        extracted_values['TCPIP.IP6_dest'] = 0xfe800000000000000000000000000000 | val

            else:
                # sam case 2
                if encoding >> 4 & 3 == 0:
                    pass
                if encoding >> 4 & 3 == 0b01:
                    pass
                if encoding >> 4 & 3 == 0b10:
                    pass
                if encoding >> 4 & 3 == 0b11:
                    pass

            #destination
            # multicast
            if encoding >> 3 & 1 == 0:
                # dac
                if encoding >> 2 & 1 == 0:
                    # dam case 1
                    if encoding & 3 == 0:
                        val = get_header_field(ip6_layer, 'destination_addr', VALUE)
                        extracted_values['TCPIP.IP6_source'] = val
                    if encoding & 3 == 0b01:
                        val = get_header_field(ip6_layer, 'destination_addr', VALUE)
                        extracted_values['TCPIP.IP6_source'] = 0xfe800000000000000000000000000000 | val
                    if encoding & 3 == 0b10:
                        val = get_header_field(ip6_layer, 'destination_addr', VALUE)
                        extracted_values['TCPIP.IP6_source'] = 0xfe800000000000000000000000000000 | 0x000000fffe000000 | (val & 0xffff)
                    if encoding & 3 == 0b11:
                        if 'IEEE802154.LL_source' in extracted_values:
                            val = extracted_values['IEEE802154.LL_source']
                            extracted_values['TCPIP.IP6_source'] = 0xfe800000000000000000000000000000 | val
                else:
                    # dam case 2
                    if encoding & 3 == 0:
                        pass
                        #parser._logger.warning("Reached illegal compression state! Are you sure everything is correct? (2)")
                    if encoding & 3 == 0b01:
                        pass
                    if encoding & 3 == 0b10:
                        pass
                    if encoding & 3 == 0b11:
                        pass
            else:
                # dac
                if encoding >> 2 & 1 == 0:
                    # dam case 3
                    if encoding & 3 == 0:
                        val = get_header_field(ip6_layer, 'destination_addr', VALUE)
                        extracted_values['TCPIP.IP6_source'] = val
                    if encoding & 3 == 0b01:
                        val = get_header_field(ip6_layer, 'destination_addr', VALUE)
                        extracted_values['TCPIP.IP6_source'] = 0xff000000000000000000000000000000 | (val & 0xffffffffff) | ((val >> 40) << 112)
                    if encoding & 3 == 0b10:
                        val = get_header_field(ip6_layer, 'destination_addr', VALUE)
                        extracted_values['TCPIP.IP6_source'] = 0xff000000000000000000000000000000 | (val & 0xffffff) | ((val >> 24) << 112)


                    if encoding & 3 == 0b11:
                        val = get_header_field(ip6_layer, 'destination_addr', VALUE)
                        extracted_values['TCPIP.IP6_source'] = 0xff020000000000000000000000000000 | (val & 0xff)

                else:
                    # dam case 4
                    if encoding & 3 == 0:
                        set_header_field(ip6_layer, 'destination_addr', SIZE, 0x6)  # part compression
                    else:
                        parser._logger.warning("Reached illegal compression state! Are you sure everything is correct? (3)")

    return extracted_values


def ble_advertisement_parser(header: dict, payload: bytes) -> dict:
    """ Parse BLE advertisement packet and extract address """
    advA = get_header_field(header, "AdvA", VALUE) if "AdvA" in header else 0
    extracted_values = dict()

    if advA != 0:
        # TODO document this better
        extracted_values["BLE.TargetA"] = advA
    return extracted_values


def ieee802154_mac_parser(header: dict, payload: bytes) -> dict:
    """ Parse IEEE802154 packets and extract source and destination information """
    extracted_values = dict()
    if  VALUE in header['destination_PAN'] and header['destination_PAN'][VALUE]:
        extracted_values['IEEE802154.PAN_source'] = get_header_field(header, 'destination_PAN', VALUE)

    if  VALUE in header['destination_addr'] and header['destination_addr'][VALUE] != 0:
        extracted_values['IEEE802154.LL_source'] = get_header_field(header, 'destination_addr', VALUE)
    
    if  VALUE in header['source_PAN'] and header['source_PAN'][VALUE] != 0:
        extracted_values['IEEE802154.PAN_dest'] = get_header_field(header, 'source_PAN', VALUE)

    if  VALUE in header['source_addr'] and header['source_addr'][VALUE] != 0:
        extracted_values['IEEE802154.LL_dest'] = get_header_field(header, 'source_addr', VALUE)

    return extracted_values


def dhcp_parser(header: dict, payload: bytes) -> dict:
    """ Parse DHCP packet and extract XID, and address """
    magic = to_int(payload[:4])
    extracted_values = dict()
    payload = payload[4:]
    if payload[0] != 0xff:
        option_type = payload[0]
        if option_type == 0:
            payload = payload[1:]

        option_len = payload[1]
        option = to_int(payload[2: (2 + option_len)])

        # now we can get do a switch on the options basically

    extracted_values['DHCP.xid'] = get_header_field(header, 'xid', VALUE)
    extracted_values['DHCP.chaddr'] = get_header_field(header, 'chaddr', VALUE)
    return extracted_values


def udp_parser(header: dict, payload: bytes) -> dict:
    """ Parse UDP and extract source/destination """
    extracted_values = dict()
    if VAL_PREFIX in header['destination']:
        extracted_values['UDP.source'] = (get_header_field(header, 'destination', VAL_PREFIX) << get_bitsize(header['destination'])) | get_header_field(header, 'destination', VALUE)
    else:
        extracted_values['UDP.source'] = get_header_field(header, 'destination', VALUE)
    
    if VAL_PREFIX in header['source']:
        extracted_values['UDP.destination'] = (get_header_field(header, 'source', VAL_PREFIX) << get_bitsize(header['source'])) | get_header_field(header, 'source', VALUE)
    else:
        extracted_values['UDP.destination'] = get_header_field(header, 'source', VALUE)
    
    return extracted_values


def generic_fcf(parser, field: dict, header: dict, pkt: str) -> (str, bool):
    """ Parse FCF and extract the frame type """
    fcf = get_field_info(field, VALUE)
    source_addr_mode = fcf >> 14
    frame_version = (fcf >> 12) & 3
    dest_addr_mode = (fcf >> 10) & 3
    pan_id_compr = (fcf >> 6) & 1
    ack_request = (fcf >> 5) & 1
    frame_pending = (fcf >> 4) & 1
    sec_enabled = (fcf >> 3) & 1
    frame_type = fcf & 7

    if get_field_info(field, VALUE) & 7 == IEEE802154_BEACON:
        return '6lowpan_MAC_Beacon', True
    if get_field_info(field, VALUE) & 7 == IEEE802154_DATA:
        return '6lowpan_MAC_Data', True
    if get_field_info(field, VALUE) & 7 == IEEE802154_COMMAND:
        return '6lowpan_MAC_Command', True
    if get_field_info(field, VALUE) & 7 == IEEE802154_ACK:
        return '6lowpan_MAC_Ack', True
    return '', True


def ieee802154_mac_data_fcf(parser, field: dict, header: dict, pkt: str) -> (str, bool):
    """ Parse FCF and extract source/dest """
    fcf = get_field_info(field, VALUE)
    source_addr_mode = fcf >> 14
    frame_version = (fcf >> 12) & 3
    dest_addr_mode = (fcf >> 10) & 3
    pan_id_compr = (fcf >> 6) & 1
    ack_request = (fcf >> 5) & 1
    frame_pending = (fcf >> 4) & 1
    sec_enabled = (fcf >> 3) & 1
    frame_type = fcf & 7
    # set all fields to size 0
    set_field_info(header['destination_PAN'], SIZE, 0) 
    set_field_info(header['destination_addr'], SIZE, 0) 
    set_field_info(header['source_PAN'], SIZE, 0) 
    set_field_info(header['source_addr'], SIZE, 0) 
    set_field_info(header['auxillary_security_header'], SIZE, 0) 

    if dest_addr_mode == 0:
        pass
    if dest_addr_mode == 1:
        fcf = (fcf & 0xf3ff)
        dest_addr_mode = 0
    if dest_addr_mode == 2:
        set_field_info(header['destination_addr'], SIZE,  2)  
    if dest_addr_mode == 3:
        set_field_info(header['destination_addr'], SIZE,  8)  
        pass

    if source_addr_mode == 0:
        pass
    if source_addr_mode == 1:
        fcf = (fcf & 0x3fff) | 0x8000
        source_addr_mode = 2
    if source_addr_mode == 2:
        set_field_info(header['source_addr'], SIZE,  2)  
        pass
    if source_addr_mode == 3:
        set_field_info(header['source_addr'], SIZE,  8)

    if pan_id_compr == 0:
        if dest_addr_mode > 0:
            set_field_info(header['destination_PAN'], SIZE, 2)
        if source_addr_mode > 0:
            set_field_info(header['source_PAN'], SIZE, 2) 

    if pan_id_compr == 1:
        if source_addr_mode > 1:# and dest_addr_mode > 1:
            set_field_info(header['destination_PAN'], SIZE, 2) 

    if frame_type == IEEE802154_DATA:
        return '6lowpan_mesh_frag', True
    return '', True


# TODO not supported yet
def sixlowpan_mesh_handler(parser, field: dict, header: dict, pkt: str) -> (str, bool):
    # check dispatch and zero out if need bbe
    dispatch = pkt[:2]
    if dispatch != '10':
        field[SIZE] = 0

        return "6lowpan", False
    field[SIZE] = 0
    # Right now we dont support parsing the mesh handler, once we do we can remove the following line
    return "6lowpan", False


def sixlowpan_fragmentation_handler(parser, field: dict, header: dict, pkt: str) -> (str, bool):
    """ Deal with 6LoWPAN fragmentaion """
    dispatch = pkt[:2]
    if dispatch != '11':
        return "6lowpan", False
    frag_type = pkt[2:5]
    if frag_type == '000':
        set_header_field(field, 'datagram_offset', SIZE, 0) 
        parser._fragement_size = int(pkt[5:16], 2)
    elif frag_type == '100':
        set_header_field(field, 'datagram_offset', SIZE, 1) 
        if len(''.join([x for x in parser._fragment_queue])) >= parser._fragement_size:
            parser._logger.debug("REACHED last fragment")
            parser._fragement_size = 0
    parser._fragment_waiting = True

    return "6lowpan", True


def sixlowpan_hc1_handler(parser, field: dict, header: dict, pkt: str) -> (str, bool):
    """ Deal with 6LoWPAN HC1 compression """
    ip6_layer = parser._parsed_protocols['IP6']
    encoding = pkt[8:16]
    # ip6 source addr
    if encoding[:2] == '01':
        set_header_field(ip6_layer, 'source_addr', SIZE, 0x8)
    if encoding[:2] == '10':
        set_header_field(ip6_layer, 'source_addr', SIZE, 0x8)
    if encoding[:2] == '11':
        set_header_field(ip6_layer, 'source_addr', COMPRESSED, True)

    # ip6 dest addr
    if encoding[2:4] == '01':
        set_header_field(ip6_layer, 'destination_addr', SIZE, 0x8)
    if encoding[2:4] == '10':
        set_header_field(ip6_layer, 'destination_addr', SIZE, 0x8)
    if encoding[2:4] == '11':
        set_header_field(ip6_layer, 'destination_addr', COMPRESSED, True)

    # traffic class and flow label
    if encoding[4] == '1':
        set_header_field(ip6_layer, 'flow_label', COMPRESSED, True) 
        set_header_field(ip6_layer, 'traffic_class_ds', COMPRESSED, True) 
        set_header_field(ip6_layer, 'traffic_class_ecn', COMPRESSED, True)  
    # next header
    if encoding[5:7] == '01': # UDP
        set_header_field(ip6_layer, 'next_header', VALUE, 17)
        set_header_field(ip6_layer, 'next_header', COMPRESSED, True)
    if encoding[5:7] == '10': # ICMP

        set_header_field(ip6_layer, 'next_header', VALUE, 0x3a)
        set_header_field(ip6_layer, 'next_header', COMPRESSED, True)
    if encoding[5:7] == '11': # TCP
        set_header_field(ip6_layer, 'next_header', VALUE, 6)
        set_header_field(ip6_layer, 'next_header', COMPRESSED, True)
    #hc2 encoding
    if encoding[7] == '1':
        parser._logger.warning("! HC2 not implemented yet")
        pass # TODO 

    return "IP6", True


def sixlowpan_udp_nhc_handler(parser, field: dict, header: dict, pkt: str) -> str:
    """ Deal with UDP next header compression (NHC) """
    pattern =  int(pkt[:5], 2)
    encoding = int(pkt[5:8], 2)
    set_header_field(header, 'length', COMPRESSED, True) 

    # checksum
    if encoding >> 2 & 1:
        set_header_field(header, 'udp_checksum', COMPRESSED, True) 
    set_header_field(header, 'destination', SIZE, 2) 
    set_header_field(header, 'source', SIZE, 2) 
        
    # ports
    if encoding & 3 == 0:
        pass #no compresserino
    if encoding & 3 == 0b01:
        set_header_field(header, 'destination', SIZE, 1) 
        set_header_field(header, 'destination', VAL_PREFIX, 0xf0) 
        
    if encoding & 3 == 0b10:
        set_header_field(header, 'source', SIZE, 1) 
        set_header_field(header, 'source', VAL_PREFIX, 0xf0) 

        
    if encoding & 3 == 0b11:
        set_header_field(header, 'destination', SIZE, 'b4') 
        set_header_field(header, 'source', SIZE, 'b4') 
        set_header_field(header, 'destination', VAL_PREFIX, 0xf0b) 
        set_header_field(header, 'source', VAL_PREFIX, 0xf0b) 


def nhc_compression_handler(parser, field: dict, header: dict, pkt: str) -> (str, bool):
    """ Compression handler specified in the 6LoWPAN yml """
    for name, f in header[field['target']][HEADER].items():
        f[COMPRESSED] = True
    return "", False


def sixlowpan_test_nhc_handler(parser, packet: str) -> (str, object, int):
    """ Wrapper to test if the packet needs UDP next heaeder compression handling """
    if packet[:5] == "11110":
        return "UDP", sixlowpan_udp_nhc_handler, 1 # in bytes

    return None, None, 0


def sixlowpan_iphc_handler(parser, field: dict, header: dict, pkt: str) -> (str, bool):
    """ Deal with 6LoWPAN IPHC compression """
    set_header_field(field, 'pattern', SIZE, 'b3') 
    set_header_field(field, 'encoding', SIZE, 'b13') 
    encoding = int(pkt[3:16], 2)   
    ip6_layer = parser._parsed_protocols['6lowpan'][HEADER]['ip6_header'][HEADER]

    # always compressed:
    set_header_field(ip6_layer, 'version', COMPRESSED, True) 
    set_header_field(ip6_layer, 'payload_len', COMPRESSED, True) 

    # TF
    if encoding >> 11 == 0b11:
        set_header_field(ip6_layer, 'flow_label', COMPRESSED, True) 
        set_header_field(ip6_layer, 'traffic_class_ds', COMPRESSED, True) 
        set_header_field(ip6_layer, 'traffic_class_ecn', COMPRESSED, True) 
        set_header_field(ip6_layer, 'compression_padding', SIZE, 0) 

    if encoding >> 11 == 0b10:
        set_header_field(ip6_layer, 'flow_label', COMPRESSED, True) 
        set_header_field(ip6_layer, 'compression_padding', SIZE, 0) 

        
    if encoding >> 11 == 0b01:
        set_header_field(ip6_layer, 'traffic_class_ds', COMPRESSED, True) 
        set_header_field(ip6_layer, 'compression_padding', SIZE, 'b2') 
        
    if encoding >> 11 == 0b00:
        set_header_field(ip6_layer, 'compression_padding', SIZE, 'b4') 
        # TODO padding???
    
    # NH
    if encoding >> 10 & 1:
        set_header_field(ip6_layer, 'next_header', COMPRESSED, True) 
        set_header_field(ip6_layer, 'next_header', "compression_function", sixlowpan_test_nhc_handler) 
        if VALUE in ip6_layer['next_header']:
            ip6_layer['next_header'].pop(VALUE)
            ip6_layer['next_header'].pop(STREAM_DATA)

    #hlim 
    if encoding >> 8 & 3== 0b01:
        set_header_field(ip6_layer, 'hop_limit', COMPRESSED, True) 
        set_header_field(ip6_layer, 'hop_limit', VALUE, 1) 
    if encoding >> 8 & 3== 0b10:
        set_header_field(ip6_layer, 'hop_limit', COMPRESSED, True) 
        set_header_field(ip6_layer, 'hop_limit', VALUE, 64) 
    if encoding >> 8 & 3== 0b11:
        set_header_field(ip6_layer, 'hop_limit', COMPRESSED, True) 
        set_header_field(ip6_layer, 'hop_limit', VALUE, 255) 

    # cid
    cid = ''
    if encoding >> 7 & 1 == 1:
        cid = pkt[16:24]
    
    # sac
    if encoding >> 6 & 1 == 0:
        # sam case 1
        if encoding >> 4 & 3 == 0:
            pass # no compression
        if encoding >> 4 & 3 == 0b01:
            set_header_field(ip6_layer, 'source_addr', SIZE, 0x8)  # part compression
        if encoding >> 4 & 3 == 0b10:
            set_header_field(ip6_layer, 'source_addr', SIZE, 0x2) 
        if encoding >> 4 & 3 == 0b11:
            set_header_field(ip6_layer, 'source_addr', COMPRESSED, True)  # full compression
            set_header_field(ip6_layer, 'source_addr', VALUE, 0xfd000000000000000000000000000000)  # full compression

    else:
        # sam case 2
        if encoding >> 4 & 3 == 0:
            set_header_field(ip6_layer, 'source_addr', SIZE, 0x0)  
            set_header_field(ip6_layer, 'source_addr', VALUE, 0x0)  # unspecified address

        if encoding >> 4 & 3 == 0b01:
            set_header_field(ip6_layer, 'source_addr', SIZE, 0x8)  # part compression
        if encoding >> 4 & 3 == 0b10:
            set_header_field(ip6_layer, 'source_addr', SIZE, 0x2) 
        if encoding >> 4 & 3 == 0b11:
            set_header_field(ip6_layer, 'source_addr', COMPRESSED, True)  # full compression

    # multicast
    if encoding >> 3 & 1 == 0:
        # dac
        if encoding >> 2 & 1 == 0:
            # dam case 1
            if encoding & 3 == 0:
                pass # no compression
            if encoding & 3 == 0b01:
                set_header_field(ip6_layer, 'destination_addr', SIZE, 0x8)  # part compression
            if encoding & 3 == 0b10:
                set_header_field(ip6_layer, 'destination_addr', SIZE, 0x2) 
            if encoding & 3 == 0b11:
                set_header_field(ip6_layer, 'destination_addr', COMPRESSED, True)  # full compression
        else:
            # dam case 2
            if encoding & 3 == 0:
                parser._logger.warning("Reached illegal compression state! Are you sure everything is correct? (2)")
            if encoding & 3 == 0b01:
                set_header_field(ip6_layer, 'destination_addr', SIZE, 0x8)  # part compression
            if encoding & 3 == 0b10:
                set_header_field(ip6_layer, 'destination_addr', SIZE, 0x2) 
            if encoding & 3 == 0b11:
                set_header_field(ip6_layer, 'destination_addr', COMPRESSED, True)  # full compression
    else:
        # dac
        if encoding >> 2 & 1 == 0:
            # dam case 3
            if encoding & 3 == 0:
                pass # no compression
            if encoding & 3 == 0b01:
                set_header_field(ip6_layer, 'destination_addr', SIZE, 0x6)  # part compression
            if encoding & 3 == 0b10:
                set_header_field(ip6_layer, 'destination_addr', SIZE, 0x4) 
            if encoding & 3 == 0b11:
                set_header_field(ip6_layer, 'destination_addr', SIZE, 0x1) 

        else:
            # dam case 4
            if encoding & 3 == 0:
                set_header_field(ip6_layer, 'destination_addr', SIZE, 0x6)  # part compression
            else:
                parser._logger.warning("Reached illegal compression state! Are you sure everything is correct? (3)")
    
    if cid:
        # TODO
        pass 

    return "", True


def sixlowpan_compression_wrapper(parser, field: dict, header: dict, pkt: str) -> (str, bool):
    """ Wrapper to analyze 6LoWPAN compression """
    if NO_COMP in field and field[NO_COMP]:
        return "IP6", False
    dispatch = pkt[:8]
    if dispatch == '01000001':
        return "IP6", False
    if dispatch == '01000010':
        return sixlowpan_hc1_handler(parser, field, header, pkt)
    if dispatch[:3] == '011':
        return sixlowpan_iphc_handler(parser, field, header, pkt)
    
    return '', False
        

IP4_FRAGMENT_MAGIC = 0xdeadbeef
def ip4_fragmentation_handler(parser, field: dict, header: dict, pkt: str) -> (str, bool):
    """ Handle IPv4 fragments, by observing flags and the datagram offset. Both return values do not matter """
    if get_header_field(header, "datagram_offset", VALUE) == 0 and (get_header_field(header, "flags", VALUE) & 1) == 0:
        # no fragment:
        return '', True 
    
    # first or subequent fragment
    parser._fragement_size = 0xdeadbeef
    if (get_header_field(header, "flags", VALUE) & 1) == 0:
        # last fragment
        parser._fragement_size = 0
    parser._fragment_waiting = True
    return '', True
