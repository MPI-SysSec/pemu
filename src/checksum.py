from .utils import *

def default_checksum(field: dict, layer: dict, upper_layer: dict) -> int:
    """
    Small handler showing the interface for implementing checksum functions. 
    The arguments should allow the handler to access all necessary information. 

    Note: if a checksum (like tcp_checksum) is not executed while assembling the target layer
    but during a later point in time, it is the checksum function's duty to make sure
    the result of the computation is inserted into the correct header field.
    This is context, which is not accessible by the caller, that checks the handler queue.

    Args:
        field: dictionary of the field the handler function is executed from
        layer: the entire current layer of the packet (which contains the field)
        uppper_layer: the next upper layer; i.e., the layer assembled previous to the current on

    Returns:
        Result of the handler's calculations as an integer
    """

    return 0xffffffff

def ip4_checksum(field: dict, layer: dict, upper_layer: dict) -> int:
    """ Calculate IPv4 checksum of current header """
    header_len = layer[META][HEADER_LEN]
    header = int_to_bytes(int(PREFIX + layer[PKT][:header_len], 2))[PREFIX_LEN:]
    s = 0 #binary sum

    for i in range(0, len(header), 2):
        if (i+1) < len(header):
            a = header[i] 
            b = header[i+1]
            s = s + (a+(b << 8))
        elif (i+1)==len(header):
            s += header[i]
        else:
            raise "Something Wrong here"

    # One's Complement
    s = s + (s >> 16)
    s = ~s & 0xffff
    s = ((s & 0xff) << 8) | ((s >> 8) & 0xff)

    return s

def short_to_be(val):
    """ Helper function """
    return val & 0xffff
    return ((val >> 8) & 0xff | ((val & 0xff) << 8))

# https://gist.github.com/david-hoze/0c7021434796997a4ca42d7731a7073a
def tcp_checksum(field: dict, layer: dict, upper_layer: dict) -> int:
    """ Calculate TCP checksum """
    if layer[META][ID] != 0x800:
        # If we have 6lowpan or ip6 we need another checksum
        if layer[META][ID] == 0x86dd or layer[META][ID] == 0x20005:
            return tcp6_checksum(field, layer, upper_layer)
        return "missing information on the ip pseudo header"
    
    if upper_layer[META][ID] != 6:
        return "Something is terribly wrong"
    
    # pseudo header checksum:
    sum = 0
    sum += short_to_be((int(layer[HEADER]['source_ip'][STREAM_DATA], 2) >> 16) & 0xffff)
    sum += short_to_be(int(layer[HEADER]['source_ip'][STREAM_DATA], 2) & 0xffff)
    sum += short_to_be((int(layer[HEADER]['destination_ip'][STREAM_DATA], 2) >> 16) & 0xffff)
    sum += short_to_be(int(layer[HEADER]['destination_ip'][STREAM_DATA], 2) & 0xffff)
    sum += short_to_be(int(layer[HEADER]['protocol'][STREAM_DATA], 2) & 0xffff)

    tcp_len = (len(upper_layer[PKT]) // 8) #tcp len in bytes
    tcp_len_be = short_to_be(tcp_len) #((tcp_len >> 8) | ((tcp_len & 0xff) << 8)) #& 0xffff
    pkt = upper_layer[PKT]
    sum += tcp_len_be

    while tcp_len > 1:
        sum += short_to_be(int(pkt[:16],2))
        pkt = pkt[16:]
        tcp_len -= 2

    if tcp_len > 0:
        # pad with zero bytes
        sum += int(pkt[:16] + '0000', 2)

    while sum >> 16:
        sum = (sum & 0xffff) + (sum >> 16)
    sum = short_to_be(sum ^ 0xffff)
    
    # Insert checksum into the upper layer, i.e., TCP
    upper_layer[HEADER]["tcp_checksum"][STREAM_DATA] = f"{sum:0{upper_layer[HEADER]['tcp_checksum'][STREAM_LEN]}b}"
    upper_layer[HEADER]["tcp_checksum"][VALUE] = sum
    return sum

def tcp6_checksum(field: dict, layer: dict, upper_layer: dict) -> int:
    """ Calculate TCP checksum, for TCP over IPv6 """
    if upper_layer[META][ID] != 6:
        return "Something is terribly wrong"
    
    ip6_layer = layer

    if layer[META][ID] == 0x20005: 
        if 'ip6_header' in layer[HEADER]:
            ip6_layer = layer[HEADER]['ip6_header']
        else:
            return "Something is terribly wrong"
    source_addr = int(ip6_layer[HEADER]['source_addr'][STREAM_DATA], 2)
    dest_addr = int(ip6_layer[HEADER]['destination_addr'][STREAM_DATA], 2)
    
    sum = 0
    tcp_len = (len(upper_layer[PKT]) // 8) #tcp len in bytes
    tcp_len_be = short_to_be(ip6_layer[HEADER]['payload_len'][VALUE]) #((tcp_len >> 8) | ((tcp_len & 0xff) << 8)) #& 0xffff
    sum += (short_to_be(6) & 0xffff)
    sum += tcp_len_be
    sum += (short_to_be(source_addr >> 112) & 0xffff)
    sum += (short_to_be(source_addr >> 96) & 0xffff)
    sum += (short_to_be(source_addr >> 80) & 0xffff)
    sum += (short_to_be(source_addr >> 64) & 0xffff)
    sum += (short_to_be(source_addr >> 48) & 0xffff)
    sum += (short_to_be(source_addr >> 32) & 0xffff)
    sum += (short_to_be(source_addr >> 16) & 0xffff)
    sum += (short_to_be(source_addr) & 0xffff)
    sum += (short_to_be(dest_addr >> 112) & 0xffff)
    sum += (short_to_be(dest_addr >> 96) & 0xffff)
    sum += (short_to_be(dest_addr >> 80) & 0xffff)
    sum += (short_to_be(dest_addr >> 64) & 0xffff)
    sum += (short_to_be(dest_addr >> 48) & 0xffff)
    sum += (short_to_be(dest_addr >> 32) & 0xffff)
    sum += (short_to_be(dest_addr >> 16) & 0xffff)
    sum += (short_to_be(dest_addr) & 0xffff)

    while sum >> 16:
        sum = (sum & 0xffff) + (sum >> 16)

    pkt = ''
    for header in ['ext_header_hop_nhc', 'ext_header_hop', 'ext_header_routing_nhc', 'ext_header_routing', 'ext_header_frag_nhc' ,'ext_header_frag', 'ext_header_dest_options_nhc', 'ext_header_dest_options', 'ext_header_mobility_nhc', 'ext_header_mobility']:
        if header in layer and PKT in layer[HEADER]:
            pkt += layer[HEADER][PKT]
    pkt += upper_layer[PKT]

    while tcp_len > 1:
        sum += short_to_be(int(pkt[:16],2))
        pkt = pkt[16:]
        tcp_len -= 2

    if tcp_len > 0:
        # pad with zero bytes
        sum += int(pkt[:16] + '0000', 2)

    while sum >> 16:
        sum = (sum & 0xffff) + (sum >> 16)
    sum = short_to_be(sum ^ 0xffff)

    # place checksum
    upper_layer[HEADER]["tcp_checksum"][STREAM_DATA] = f"{sum:0{upper_layer[HEADER]['tcp_checksum'][STREAM_LEN]}b}"
    upper_layer[HEADER]["tcp_checksum"][VALUE] = sum
    return sum

def udp_checksum(field: dict, layer: dict, upper_layer: dict) -> int:
    """ Calculate the UDP checksum """
    if layer[META][ID] == 0x800:
        return udp_ip4_checksum(field, layer, upper_layer)
    if layer[META][ID] == 0x86dd:
        return udp_ip6_checksum(field, layer, upper_layer)
    if layer[META][ID] == 0x2005:
        return udp_ip6_checksum(field, layer, upper_layer)

    return "Something is terribly wrong"
    
    
def udp_ip4_checksum(field: dict, layer: dict, upper_layer: dict) -> int:
    """ Calculate the UDP checksum over IPv4"""
    sum = 0
    sum += (int(layer[HEADER]['source_ip'][STREAM_DATA],2) >> 16) & 0xffff
    sum += int(layer[HEADER]['source_ip'][STREAM_DATA],2) & 0xffff
    sum += (int(layer[HEADER]['destination_ip'][STREAM_DATA],2) >> 16) & 0xffff
    sum += int(layer[HEADER]['destination_ip'][STREAM_DATA],2) & 0xffff
    sum += int(layer[HEADER]['protocol'][STREAM_DATA],2)

    udp_len = (len(upper_layer[PKT]) // 8) #tcp len in bytes
    pkt = upper_layer[PKT]
    sum += udp_len

    while udp_len > 1:
        sum += int(pkt[:16],2)
        pkt = pkt[16:]
        udp_len -= 2

    if udp_len > 0:
        sum += int(pkt[:16] + '0000', 2)

    while sum >> 16:
        sum = (sum & 0xffff) + (sum >> 16)
    sum ^= 0xffff

    # Place checksum
    upper_layer[HEADER]["udp_checksum"][STREAM_DATA] = f"{sum:0{upper_layer[HEADER]['udp_checksum'][STREAM_LEN]}b}"
    return sum


def udp_ip6_checksum(field: dict, layer: dict, upper_layer: dict) -> int:
    """ Calculate the UDP checksum over IPv6 """
    ip6_layer = layer
    if 'ip6_header' in ip6_layer[HEADER]:
        ip6_layer = layer[HEADER]['ip6_header']
    sum = 0
    for i in range(0, 128, 16):
        sum += (int(ip6_layer[HEADER]['source_addr'][STREAM_DATA], 2) >> (112-i)) & 0xffff

    for i in range(0, 128, 16):
        sum += (int(ip6_layer[HEADER]['destination_addr'][STREAM_DATA], 2) >> (112-i)) & 0xffff
    

    sum += int(ip6_layer[HEADER]['next_header'][STREAM_DATA], 2)
    sum += int(ip6_layer[HEADER]['payload_len'][STREAM_DATA], 2)
    udp_len = (len(upper_layer[PKT]) // 8) #tcp len in bytes

    pkt = upper_layer[PKT]
    sum += udp_len
    while udp_len > 1:
        sum += int(pkt[:16],2)
        pkt = pkt[16:]
        udp_len -= 2

    if udp_len > 0:
        # pad with zero bytes
        sum += int(pkt[:16] + '0000', 2)

    while sum >> 16:
        sum = (sum & 0xffff) + (sum >> 16)
    sum ^= 0xffff

    # place checksum
    upper_layer[HEADER]["udp_checksum"][STREAM_DATA] = f"{sum:0{upper_layer[HEADER]['udp_checksum'][STREAM_LEN]}b}"
    return sum

def modbus_crc(field: dict, layer: dict, upper_layer: dict) -> int:
    """ Calculate checksum for Modbus """
    temp = 0xffff
    data = layer[HEADER]['id'][VALUE].to_bytes(1, "big") + layer[HEADER]['fct'][VALUE].to_bytes(1, "big") + layer[HEADER]['remaining_len'][VALUE].to_bytes(1, "big") + layer[HEADER]['modbus_data'][VALUE].to_bytes(layer[HEADER]['modbus_data'][SIZE], "big")
    data_len = len(data)
    for i in range(data_len):
        temp = temp ^ data[i]
        for j in range(8):
            flag = temp & 0x0001
            temp >>= 1
            if flag:
                temp ^= 0xa001

    temp2 = temp >> 8
    temp = (temp << 8) | temp2
    temp &= 0xffff
    return temp
