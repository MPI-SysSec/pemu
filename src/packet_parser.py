from .utils import *
from io import TextIOWrapper
from .parsing_handler import *

layer_parser = {"Ethernet" : ethernet_parser,
                 "IP4" : ip4_parser,
                 "TCP" : tcp_parser,
                 "BLE_adv_ADV_IND" : ble_advertisement_parser,
                 "BLE_adv_ADV_DIRECT_IND" : ble_advertisement_parser,
                 "BLE_adv_ADV_NONCONN_IND" : ble_advertisement_parser,
                 "BLE_adv_ADV_SCAN_IND" : ble_advertisement_parser,
                 "BLE_adv_ADV_EXT_IND" : ble_advertisement_parser,
                 "BLE_adv_AUX_ADV_IND" : ble_advertisement_parser,
                 "BLE_adv_AUX_SYNC_IND" : ble_advertisement_parser,
                 "BLE_adv_AUX_CHAIN_IND" : ble_advertisement_parser,
                 "BLE_adv_CONNECT_IND" : ble_advertisement_parser,
                 "BLE_adv_AUX_CONNECT_REQ" : ble_advertisement_parser,
                 "BLE_adv_AUX_CONNECT_RSP" : ble_advertisement_parser,
                 "BLE_adv_SCAN_REQ": ble_advertisement_parser,
                 "BLE_adv_AUX_SCAN_REQ": ble_advertisement_parser,
                 "BLE_adv_SCAN_RSP": ble_advertisement_parser,
                 "BLE_adv_AUX_SCAN_RSP": ble_advertisement_parser,
                 "6lowpan_MAC_Beacon": ieee802154_mac_parser,
                 "6lowpan_MAC_Data": ieee802154_mac_parser,
                 "6lowpan_MAC_Command": ieee802154_mac_parser,
                 "DHCP": dhcp_parser,
                 "IP6": ip6_parser,
                 "6lowpan": sixlowpan_parser,
                 "ARP": arp_parser,
                 "UDP": udp_parser}

EPHEMERAL_ATTR_NAMES = [
    "_snapshot", "_apriori_vals", "_logger", "_dirty", "_parsed_protocols", "_fragment_queue" # maybe parsed protocols
]

class PacketParser:
    """ 
    Module for the parsing of firmware transmitted packets. 
    """
    _parsed_protocols: dict
    _static_parsed_protocols: dict
    _apriori_vals: dict
    _output_file: str
    _protocol_offset: int
    _fragment_queue: list
    _fragment_size: int
    _fragment_waiting: bool
    _new_protocol: bool
    _sent_cursor: int
    _snapshot = dict()
    _no_protocol: bool
    _symbol_change: bool
    _dirty: bool

    def __init__(self, config: dict, protocol_state: list, output_file:str=None, symbol_change=True, log_level=logging.WARNING):
        """ Initialization of the module """
        logging.basicConfig()
        self._logger = logging.getLogger(__name__)
        self._logger.setLevel(log_level)
        self._request_analysis = False
        self._new_val = False
        self._new_protocol = False
        self._no_protocol = False
        self._parse_config(config, protocol_state)
        self._symbol_change = symbol_change
        self._dirty = False

        self._output_file = None
        if output_file:
            self._output_file = output_file
        self._logger.debug(f"Initializing the following protocols:  {', '.join([str(x) for x in self._parsed_protocols.keys()])}")

        self._fragment_queue = list()
        self._fragement_size = 0
        self._fragment_waiting = False
        self._sent_cursor = 0
        self._static_parsed_protocols = copy.deepcopy(self._parsed_protocols)
        return
    

    def take_snapshot(self):
        """ Take snapshots of non ephemeral attributes """
        for attr_name, value in self.__dict__.items():
            if attr_name in EPHEMERAL_ATTR_NAMES:
                continue

            self._snapshot[attr_name] = getattr(self, copy.deepcopy(attr_name))
        return

    
    def restore_snapshot(self):
        """ Restore parser from snapshot, if something was modified """
        if not self._dirty:
            # If nothing was changed we don't need to restore anything
            return
        self._dirty = False
        for attr_name, val in self._snapshot.items():
            setattr(self, attr_name, copy.deepcopy(self._snapshot[attr_name]))

        self._fragment_queue = list()
        self._parsed_protocols = self._static_parsed_protocols
        return


    def discard_snapshot(self):
        pass


    def _parse_config(self, config: dict, protocol_seq: list):
        """ PArse the network config and extract used protocols and apriori values """
        # The config is only used to include any a-priori values
        if config == None:
            config = dict()
        self._parsed_protocols = dict()
        self._apriori_vals = dict()

        for packet in protocol_seq:
            for protocol in packet:
                if protocol in self._parsed_protocols:
                    continue
                
                if protocol == "any":
                    # skip (for now)
                    continue
                self._parsed_protocols[protocol] = load_protocol(protocol)

        self._protocol_offset = 0 # Used to differntiate between protocols with the same IDs from different stacks
        if 'BLE_PHY' in self._parsed_protocols:
            self._protocol_offset = 0x10000
        if "IEEE802154_PHY" in self._parsed_protocols:
            self._protocol_offset = 0x20000

        if "static" in config:
            self._no_protocol = True

        if not APRIORI in config:
            return
        
        for name, val in config[APRIORI].items():
            self._apriori_vals[name] = val

            # also add linked rules; e.g., if ip source is set add rule for dhcp
            if name in apriori_rules:
                self._apriori_vals[apriori_rules[name]] = val
       
        return


    def set_output_file(self, output_file: str):
        """ Set the output file where new information is written to """
        self._output_file = output_file
        return

    def _check_and_update_parsed(self, protocol: str):
        if protocol in self._parsed_protocols:
            return
        
        self._logger.debug(f"Parsing new protocol: {protocol}")
        self._new_protocol = True
        # We do not always answer. BLE has differentiates between request and responses. Similar IEEE802154 ACKs
        self._parsed_protocols[protocol] = load_protocol(protocol)
        return

    def _check_and_update_field_size(self, field: dict):
        if (STREAM_LEN in field) and (field[STREAM_LEN] == get_bitsize(field)):
            return
        field[STREAM_LEN] = get_bitsize(field)
        return

    def _extract_le_field(self, data: str):
        """ Extract data from a field with little endianess """
        data = data + (32 - (len(data) % 32)) * '0' if (len(data) % 32) != 0 else data
        le_data = ''
        for i in range(0, len(data), 32):
            le_data += data[i + 24: i + 32]
            le_data += data[i + 16: i + 24]
            le_data += data[i + 8: i + 16]
            le_data += data[i + 0: i + 8]

        return int(le_data, 2)


    def _extract_field(self, field: dict, packet: str, meta: dict):
        """ Wrapper for extracting the data from a field """
        field[STREAM_DATA] = packet[:get_field_info(field, STREAM_LEN)]
        if not field[STREAM_DATA]:
            return -1
        if FIELD_ENDIAN in meta and meta[FIELD_ENDIAN] == "le":
            field[VALUE] = self._extract_le_field(get_field_info(field, STREAM_DATA))
        else:
            field[VALUE] = int(get_field_info(field, STREAM_DATA),2)

        return packet[get_field_info(field, STREAM_LEN):]


    def _to_voting_dict(self, parsed_dict: dict):
        """ Transform a dict into its voting version """
        voting_dict = dict()
        for key, val in parsed_dict.items():
                voting_dict[key] = {val: 1}
            
        if self._new_val == True and self._symbol_change:
            self._request_analysis = True
            return {'network': voting_dict, 'new_val': True}
        
        return {'network': voting_dict}


    def _update_voting_dict(self, voting_dict: dict, parsed_dict: dict):
        """ Update the voting dictionary from a parsed dictionary """
        for key, val in parsed_dict.items():
            if not key in voting_dict:
                voting_dict[key] = {val: 1}
                continue

            if not val in voting_dict[key]:
                voting_dict[key][val] = 1
                continue
                    
            voting_dict[key][val] += 1

        return

    def _write_result_to_file(self, parsed_dict: dict):
        """ 
        Write the parsing results to a given file.
        Use a voting format. If a value already exist increase its vote, else init it to 1
        """
        if not self._output_file or not self._new_val:
            return

        cur_state = None
        if os.path.isfile(self._output_file):
            cur_state = load_output_file(self._output_file)

        # check for new vals
        force_save = False
        if not cur_state:
            force_save = True
            save_to_output_file(self._to_voting_dict(parsed_dict), self._output_file, force_save)
            return

        if 'network' in cur_state:
            self._update_voting_dict(cur_state['network'], parsed_dict)
        else:
            cur_state['network'] = self._to_voting_dict(parsed_dict)['network']

        if self._new_val and self._symbol_change:
            self._request_analysis = False
            cur_state['new_val'] = True
            force_save = True

        # overwrite
        save_to_output_file(cur_state, self._output_file, force_save)
        return

    def _write_protocol_to_file(self, protocols: list, cursor: int):
        """ if  we detected a new protocol, we might want to write it to the output file """
        needs_response, response =  check_response(protocols)
        if not needs_response or not self._symbol_change or not self._output_file:
            # not all packets need a repsonse (ACKs for example), don't continue if there is no output file
            return

        cur_state = load_output_file(self._output_file)
        force_save = False
        if not cur_state:
            # If nothing written yet, always write
            force_save = True
            save_to_output_file({'new_protocols': {cursor: response}}, self._output_file, force_save)
            return

        if not 'new_protocols' in cur_state:
            # the current output file does not contain any new protocols yet, always write them
            force_save = True
            cur_state['new_protocols'] = {cursor: response}
        else:
            # If there are already new protocols compare the cursors and add the protocol
            if cursor in cur_state['new_protocols']:
                old_protocols = cur_state['new_protocols'][cursor]
                if old_protocols == response:
                    # nothing to do as it alread exists
                    return
                # metric for now is to choose the packet with more protocols
                if len(response) > len(old_protocols):
                    force_save = True
                    cur_state['new_protocols'][cursor] = response
            else:
                cur_state['new_protocols'][cursor] = response

        save_to_output_file(cur_state, self._output_file, force_save)
        return


    def _layer_analysis(self, layer: str, header: dict, payload: bytes):
        """ For each layer, check if there is analysis function. If that is  the case, call it """
        if not layer in layer_parser:
            return {}
        
        extracted = layer_parser[layer](header, payload)
        # if these values are already set apriori, discard them
        self._new_val = False
        for name in extracted:
            if name not in self._apriori_vals:
                self._new_val = True

        return extracted


    def _layer_sanity_check(self, cur_layer: str, next_layer: str, network_tree: Tree) -> str:
        """
        E.g., in TCP or UDP the destination port may point to a weong layer (e.g., Ethernet, TCP, ...).
        Therefore, we compare the current and next layer with the network tree to verify a valid packet.
        """
        subtree = network_tree.find_node(cur_layer)
        if next_layer not in subtree.get_child_names():
            return None
        return next_layer


    def _extract_body_length(self, header: dict, header_len: int) -> int:
        """ Calculate body length given a header and the header length in bytes(!)"""
        lens = list()
        for name, field in header.items():
            if get_field_info(field, TYPE) == T_LENGTH:
                if VALUE in field:
                    lens.append((field[VALUE], get_field_info(field, L_SCOPE), get_field_info(field, L_FORMAT)))

        for val, scope, format in lens:
            if scope == L_BODY:
                return val * multipliers[format]
            
            elif scope == L_EVERYTHING:
                return (val * multipliers[format]) - header_len

        return 0
    

    def _parse_payload(self, payload: str, payload_len: int):
        """ Parse payload, which is given as a binary string """
        if payload_len:
            trimmed_payload = payload[:payload_len * 8]
        elif payload:
            trimmed_payload = payload
            payload_len = len(trimmed_payload) // 8
        return    
        

    def _parse_handler(self, field: dict, header: dict, pkt: str) -> (str, bool):
        """ Check if handler is implement and call it; All handlers (for now) return the next layer """
        handler = ''
        if HANDLER in field:
            handler = get_field_info(field, HANDLER)
        elif COND_HANDLER in field:
            handler = get_field_info(field, COND_HANDLER)
        elif T_NESTED in field:
            handler = get_field_info(field, T_NESTED)

        func_obj = import_parsing_handler(handler)
        if not func_obj:
            return '', False

        self._logger.debug(f"Calling {func_obj}")
        return func_obj(self, field, header, pkt)


    def parse_packet(self, packet: bytes, cur_packet: list, cursor: int, network_tree: Tree, channel=-1):
        """
        Given a packet, parse it layer by layer and analyze the individual layers.
        Arguments:
            packet: binary representation of the packet
            cur_packet: list of the protocols in the next packet, which would be sent by the firmware
            cursor: point to the last PEMU sent packet
            network_tree: The current network tree
            channel: For some network stacks (mainly BLE), we need meta information on the used channel to decide, whether we are
                     dealing with an advertisement or a data packet. 
        """
        if not packet:
            return False
        # (re)set some values
        self._request_analysis = False
        self._dirty = True
        self._fragment_waiting = False
        cur_layer = cur_packet[0] # We assume the lowest layer to always be the same 
        next_layer_compressed = None
        cutoff_index = 0
        parsed_vals = dict()
        real_packet = list()

        # Main loop that goes layer by layer until there is none left
        while cur_layer:
            next_layer = ''
            body_len = -1

            self._check_and_update_parsed(cur_layer)
            meta = self._parsed_protocols[cur_layer][META]
            header = self._parsed_protocols[cur_layer][HEADER]
            # catch offset changes:
            if cur_layer == "6lowpan":
                self._protocol_offset = 0
            real_packet.append(cur_layer)
            
            if next_layer_compressed:
                cur_layer, compression_function, cutoff_index = next_layer_compressed(self, bin_packet)
                compression_function(self, None, header, bin_packet)
                packet = packet[cutoff_index:]

            next_layer_compressed = None
            cutoff_index = 0


            # transform the packet into a binary represantion with regards to the endianess
            if meta[ENDIAN] == LITTLE_ENDIAN:
                packet = bytes_change_endianess_32(packet)
                bin_packet = f"{to_int(packet):0{len(packet) * 8}b}"
            else:
                bin_packet = f"{to_int(packet):0{len(packet) * 8}b}" # TO binary string, prepended with zeroes!

            len_start = len(bin_packet)

            # loop over header and extract fields
            for name, field in header.items():
                # If a field has no/zero size, or it is marked as compressed by another layer skip this field
                if is_not_unpack(field):
                    if get_field_type(field) == T_POINTER and VALUE in field:
                        next_layer = resolve_protocol_id(field[VALUE])
                    if get_field_type(field) == T_POINTER and "compression_function" in field:
                        next_layer_compressed = field["compression_function"]
                    continue

                # Nested fields need to be dealt with seperately
                # First evaluate any handler; sometimes a nested field may not be used at all
                # next iteratively fill the nested fields with data 
                # Afterward, continue with the next field
                if get_field_info(field, TYPE) == T_NESTED: 

                    if T_NESTED in field:
                        if not next_layer:
                            next_layer, is_used = self._parse_handler(field, header, bin_packet)
                        else:
                            _, is_used = self._parse_handler(field, header, bin_packet)

                        if not is_used:
                            continue
                    
                    for nested_name, nested_field in get_field_info(field, HEADER).items():
                        if is_not_unpack(nested_field):
                            if get_field_type(nested_field) == T_POINTER and VALUE in nested_field:

                                next_layer = resolve_protocol_id(nested_field[VALUE])
                            if get_field_type(nested_field) == T_POINTER and "compression_function" in nested_field:
                                next_layer_compressed = nested_field["compression_function"]
                            continue 
                        self._check_and_update_field_size(nested_field)
                        bin_packet = self._extract_field(nested_field, bin_packet, get_field_info(field, META))

                        self._logger.debug(f"{nested_name}: {nested_field[VALUE]}")
                        if get_field_type(nested_field) == T_POINTER and VALUE in nested_field:
                            #self._logger.debug(f"4")
                            next_layer = resolve_protocol_id(nested_field[VALUE])
                        if bin_packet == -1:
                            return False
                    continue

                # set the bit sizes of the field
                self._check_and_update_field_size(field)

                # if a handler is associated with a field, it may need to be executed before parsing the field
                # In some cases handlers may give information on the next layer; if it is already known ignore the handler output
                # If the field is markes as opaque do not consume the packet input and instead continue to the next field
                if HANDLER in field or COND_HANDLER in field and get_field_info(field, TYPE) != T_NESTED:
                    if self._extract_field(field, bin_packet, meta) == -1:
                        return False

                    if not next_layer:
                        next_layer, _ = self._parse_handler(field, header, bin_packet)
                    else:
                        self._parse_handler(field, header, bin_packet)
                    
                    if OPAQUE in field and get_field_info(field, OPAQUE):
                        continue
                bin_packet = self._extract_field(field, bin_packet, meta)
                if bin_packet == -1:
                    return False
                self._logger.debug(f"{name}: {field[VALUE]}")
                # Compare length information with the actual length of the packet; if necessary shorten the body
                if get_field_info(field, TYPE) == T_LENGTH:
                    if get_field_info(field, L_SCOPE) == L_BODY:
                        body_len = get_field_info(field, VALUE) * multipliers[get_field_info(field, L_FORMAT)] # in byte

                # Store values that point to the next layer
                if get_field_info(field, TYPE) == T_POINTER and not next_layer:
                    next_layer = resolve_protocol_id(get_field_info(field, VALUE) | self._protocol_offset)


            self._logger.debug(header)
            if cur_layer == "BLE_adv_channel_pdu" and bin_packet[:8] == '00000000':
                bin_packet = bin_packet[8:]
            # post-processing:
            packet = packet[((len_start - len(bin_packet))//8):] # remove parsed bytes from the packet
            
            # if we found a length field, check if we can cut down the packet a little bit
            if body_len != -1 and body_len < len(packet):
                packet = packet[:body_len + 1]

            # call parsing handler
            parsed_vals.update(self._layer_analysis(cur_layer, header, packet))
           
            if not next_layer and network_tree.find_node(cur_layer)._chain_next_one:
                next_layer = network_tree.find_node(cur_layer).get_children()[0]

            # sanity check whether next layer is sane
            if not next_layer and next_layer_compressed:

                next_layer, compression_function, cutoff_index = next_layer_compressed(self, bin_packet)

            next_layer = self._layer_sanity_check(cur_layer, next_layer, network_tree)
            if not next_layer:
                if network_tree._data != "Ethernet":
                    # check if  we have a channel; e.g., in bluetooth the lowest layer does not
                    if channel != -1:
                        if channel in [37, 38, 39]:
                            next_layer = 'BLE_adv_channel_pdu'
                        if channel in range(37):
                            next_layer = 'BLE_data_channel_pdu'
                        channel = -1
                        # otherweise we reached the payload
                    else:
                        body_len = self._extract_body_length(header, (len_start - len(bin_packet)) // 8) #TODO this gives wring values??? see open fuzzware
                        self._parse_payload(bin_packet, body_len)
                        # TODO check if packet is known; and if not add that information to the output file
                        if self._new_protocol and not self._no_protocol: # This allows us to survive fragmentation
                            self._write_protocol_to_file(real_packet, cursor)
                            self._new_protocol = False

            # account for fragmentation
            # if we received a new fragment, which is not the last one stop parsing
            # otherwise, assemble the fragments and hand them over to the next layer
            if self._fragment_waiting:
                if self._fragement_size:
                    # waiting for more fragments; halt for now
                    self._fragment_queue.append(bin_packet)
                    break
                if self._fragment_queue:
                    if not self._fragement_size:
                        self._logger.debug("Assembling fragments")
                        bin_packet = ''.join([x for x in self._fragment_queue]) + bin_packet
                        # = int_to_bytes(int(bin_packet, 2))
                        packet = bitstring_to_bytes(bin_packet)

                self._fragment_waiting = False

            # go to next layer    
            cur_layer = next_layer
            
        self._write_result_to_file(parsed_vals)
        return self._request_analysis

