from .utils import *

place_data = be_place_data
NOT_ENOUGH_FUZZ = 0x12348765
OK = 1
EPHEMERAL_ATTR_NAMES = [
    "_waiting_fragments", "_handler_queue", "_snapshot", "_logger", "_consumed_fuzz", "_dirty", "_protocols", "_apriori_knowledge"
]

class Packer:
    """ Packer module which is responsible for encapsulating packets and storing the data across a run """
    _protocols: dict
    _static_protocols: dict
    _logger: logging
    _get_bytes: types.FunctionType
    _handler_queue: list
    _waiting_fragments: dict
    _apriori_knowledge: dict
    _static_apriori_knowledge: dict
    _faulty_layer: str
    _fault_probability: int
    _snapshot = dict()
    _ran_out_of_fuzz = bool
    _consumed_fuzz = list()
    _fuzz_consumed_per_packet: int
    _dirty: bool

    def __init__(self, config: dict, protocol_state: list, get_bytes: types.FunctionType, log_level=logging.WARNING):
        logging.basicConfig(level=logging.WARNING, format='%(message)s')
        self._logger = logging.getLogger(self.__class__.__name__)
        self._logger.setLevel(log_level)

        self._handler_queue = list()
        self._waiting_fragments = dict()
        self._get_bytes = get_bytes
        self.nuke_layer = None
        self._ran_out_of_fuzz = False
        self._fuzz_consumed_per_packet = 0
        self._parse_config(config, protocol_state)
        self._static_protocols = copy.deepcopy(self._protocols)
        self._static_apriori_knowledge = copy.deepcopy(self._apriori_knowledge)
        self._dirty = False


    def take_snapshot(self):
        """ We need to maintain our own snapshot. As the ANI is not able to store complex objects (like Packer) """
        for attr_name, value in self.__dict__.items():
            if attr_name in EPHEMERAL_ATTR_NAMES:
                continue

            self._snapshot[attr_name] = getattr(self, copy.deepcopy(attr_name))
        return

    
    def restore_snapshot(self):
        """ Restore the saved snapshot; Use a dirty flag to avoid unnecessary restores """
        if not self._dirty:
            # If nothing was changed we don't need to restore anything
            return
        self._dirty = False

        for attr_name, val in self._snapshot.items():
            setattr(self, attr_name, copy.deepcopy(self._snapshot[attr_name]))

        self._protocols = self._static_protocols
        self._apriori_knowledge = self._static_apriori_knowledge
        self._consumed_fuzz = list()
        self._handler_queue = list()
        self._waiting_fragments = dict()
        return


    def discard_snapshot(self):
        pass


    def _switch_to_zero_randomness(self):
        """ For probing we want to switch our fuzz byte source to true randomness """
        self._get_bytes = zero_rand
        return


    def _get_fuzz(self, n: int) -> bytes:
        """
        Wrapper function for getting fuzz bytes, which logs the taken bytes.

        Args:
            n:  number of fuzz bytes needed
        Returns:
            n fuzz bytes
        """
        self._logger.debug(f"[get_fuzz] entering {self._get_bytes}:{n:#0x}:{self._ran_out_of_fuzz}")
        fuzz_bytes = self._get_bytes(n)
        if n > 0 and not fuzz_bytes:
            self._ran_out_of_fuzz = True
            return b'\x00' * n

        self._fuzz_consumed_per_packet += n
        self._logger.debug(f"[get_fuzz] got {fuzz_bytes}")
        self._consumed_fuzz.extend([x for x in fuzz_bytes])
        return fuzz_bytes


    def _parse_config(self, config: dict, protocol_seq: list):
        """ Parse the supplied network config for faults and apriori values """
        # faults first
        self._fault_probability = DEFAULT_PROBABILITY
        self._faulty_layer = None
        if 'faults' in config:
            self._faulty_layer = config['faults']['target']
            self._fault_probability = config['faults']['probability'] if 'probability' in config['faults'] else DEFAULT_PROBABILITY
            if self._fault_probability < 1:
                self._fault_probability = int(self._fault_probability * 100)


        self._protocols = dict()
        self._apriori_knowledge = dict()
        # Load all protocols from protocol database
        for packet in protocol_seq:
            for protocol in packet:
                if protocol in self._protocols:
                    continue
                
                if protocol == "any":
                    # skip (for now)
                    continue
                self._protocols[protocol] = load_protocol(protocol)
                
        # Get apriori values
        if not config or APRIORI not in config:
            return

        # first check if given values lead to other necessary initializations
        gen_apriori = dict()
        for name in config[APRIORI].keys():
            if name in apriori_rules:
                gen_apriori[apriori_rules[name]] = config[APRIORI][name]

        # if there are add them to the apriori dict
        if gen_apriori:
            config[APRIORI] = {**config[APRIORI], **gen_apriori}

        # fill in values into the internal state
        for name, entry in config[APRIORI].items():
            if isinstance(entry, str):
                try:
                    if entry[:2] == '0x':
                        entry = int(entry, 16)
                    elif isnumeric(entry):
                        entry = int(entry)
                except:
                    pass

            protocol, field = name.split('.')

            if protocol not in self._protocols:
                self._apriori_knowledge[name] = entry
                continue

            self._protocols[protocol][HEADER][field][VALUE] = entry
            if (self._protocols[protocol][HEADER][field][TYPE] == T_FUZZED or 
                self._protocols[protocol][HEADER][field][TYPE] == T_REFERENCE):
                self._protocols[protocol][HEADER][field][TYPE] = T_DATA

        return


    def _choose_fault_layer(self, pkt: list):
        """
        If fault injection is enabled and no fault layer has been selected yet, randomly choose one from the packet current protocols
        """
        if self._faulty_layer != 'all' and self._faulty_layer in pkt:
            return OK
        dice = self._get_fuzz(1)
        if self._ran_out_of_fuzz:
            return NOT_ENOUGH_FUZZ
       
        dice = (int.from_bytes(dice, "big") ^ 0xff) % len(pkt)
        self._faulty_layer = (pkt)[dice]
        return OK


    def has_fragments_waiting(self) -> bool:
        """
        Returns whether there are any outstanding fragments that need to be dealt with before sending
        a new packet
        """
        return len(self._waiting_fragments) > 0


    def _is_handshake(self, packet: list) -> bool:
        """
        Check whether any of the packets protocols requires a handshake. If so reduce the handshake counter
        of the lowest layer that requires a handshake. Adapt the packet accordingly.

        Args:
            packet: List represntation of the packet

        Returns:
            Bool: Whether a handshake needs to happen
        """
        for layer in packet:
            if HANDSHAKE in self._protocols[layer][META] and self._protocols[layer][META][HANDSHAKE] > 0:
                self._protocols[layer][META][HANDSHAKE] = self._protocols[layer][META][HANDSHAKE] - 1
                # pop remaining layers if there are any
                while packet.index(layer) + 1 < len(packet):
                    packet.pop(packet.index(layer) + 1)
                return True
        
        return False
    

    def _import_configs(self, packet: list):
        """ Import missing configs """
        for layer in packet:
            if not layer in self._protocols:
                self._protocols[layer] = load_protocol(layer)
        return


    def get_packet(self, packet: list) -> (bytes, bool):
        """
        Assemble a packet from a list representation

        Args:
            packet: List representation of the packet

        Returns:
            Binary data, which represents the assembled packet
        """

        global place_data
        cur_pkt = list(packet)

        if self._ran_out_of_fuzz:
            # If the last try to get a packet ran out of fuzz, reset and try again
            self._consumed_fuzz = self._consumed_fuzz[:(len(self._consumed_fuzz) - self._fuzz_consumed_per_packet)]
            self._ran_out_of_fuzz = False

        self._fuzz_consumed_per_packet = 0
        self._dirty = True

        self._import_configs(packet)
        handshake =  self._is_handshake(cur_pkt)

        # If there is a handshake we only encapsulate up to the handshaking layer until the handshake is done
        if handshake:
            self._protocols[cur_pkt[-1]][BODY][SIZE] = 0
            previous_layer = packet[packet.index(cur_pkt[-1]) + 1] if len(packet) > len(cur_pkt) else None
        else:
            # Check for fragments - only assemble body if not framents are waiting
            if not self.has_fragments_waiting():
                if self._assemble_body(cur_pkt[-1]) == NOT_ENOUGH_FUZZ:
                    return b''
                previous_layer = None
                
            else:
                # adapt packet, and pick lowest fragmented layer
                frag_packet = []
                frag_layer = [x for x in self._waiting_fragments.keys()][0]
                for layer in cur_pkt:
                    if layer == frag_layer:
                        break               
                    frag_packet.append(layer)
                previous_layer = frag_layer
                cur_pkt = frag_packet
            
        # Chose a layer for deliberate (faulty) mutations
        if self._choose_fault_layer(cur_pkt) == NOT_ENOUGH_FUZZ:
            return b''
        # In a fuzzer-driven way set specified default values (e.g., broadcast addresses)
        if self.protocol_specific_changes(packet) == NOT_ENOUGH_FUZZ:
            return b''

        # Actually go through packet and assemble headers
        for layer in reversed(cur_pkt):
            place_data = be_place_data if (FIELD_ENDIAN not in self._protocols[layer][META] or self._protocols[layer][META][FIELD_ENDIAN] == BIG_ENDIAN) else le_place_data
            # First parse the upper layer payload, and then assemble the header
            self._parse_payload(self._protocols[layer], previous_layer)
            if self._assemble_header(self._protocols[layer], cur_pkt, previous_layer) == NOT_ENOUGH_FUZZ:
                return b''
            
            # Check if we need to overwrite the entire layer
            if self.nuke_layer == layer:
                if self._entire_layer_fuzzed(layer) == NOT_ENOUGH_FUZZ:
                    return b''
            
            previous_layer = layer

        # Add prefix to not miss leading zeroes during conversion
        pkt = PREFIX + self._protocols[previous_layer][PKT]
        return int_to_bytes(int(pkt,2))[PREFIX_LEN:]
    

    def _switch_endianess(self, layer: dict):
        """ 
        If needed switch the endianess of a layer's assembled paket.
        Pakets are assembled as big endian. Therefore, switching is only
        necessary if the endianess is little endian
        """
        if layer[META][ENDIAN] == BIG_ENDIAN:
            return
        
        pkt = layer[PKT]
        length = len(pkt)
        pkt_int = int(PREFIX + pkt, 2)
        pkt_bytes = to_int(le_to_bytes(pkt_int))
        layer[PKT] = f"{pkt_bytes:0{length}b}"[PREFIX_LEN_BIN:] 
        return     

    def _assemble_body(self, layer: str):
        """ Assemble the body, i.e., the payload of the highest layer of the packet """
        if not layer in self._protocols:
            self._protocols[layer] = load_protocol(layer)

        body = self._protocols[layer][BODY]
        if type(body[SIZE]) == str and body[SIZE] == T_FUZZED:
            # If size is fuzzed, select a random size
            dice = self._get_fuzz(1)
            if self._ran_out_of_fuzz:
                return NOT_ENOUGH_FUZZ 
            body[SIZE] = int.from_bytes(dice, "big")
            if MAX_LEN in body:
                if body[SIZE] > body[MAX_LEN]:
                    body[SIZE] = body[MAX_LEN]


        size = get_bytesize(body)
        b_size = get_bitsize(body)
        
        if size == 0:
           body[STREAM_DATA] = ''
           return OK

        # Deal with fixed values/handlers in the body
        if VALUE in body:
            if type(body[VALUE]) == str:
                value = int(body[VALUE].encode('ascii').hex(),16)
            elif type(body[VALUE]) == int:
                value = body[VALUE]
            elif type(body[VALUE]) == bytes:
                value = int(body[VALUE].hex(), 16)
            else:
                self._logger.error("[!] Payload body is errounous")

        elif HANDLER in body:
            if not H_RESOLVED in body:
                resolve_handler(body, HANDLER)

            value = body[H_RESOLVED](body, self._protocols[layer], None, self._get_fuzz)
            if self._ran_out_of_fuzz:
                return NOT_ENOUGH_FUZZ
            b_size = len(f"{value:0b}")
        
        else:
            # no vals/handler: fuzzed payload
            fuzzing_data = self._get_fuzz(size)
            if self._ran_out_of_fuzz:
                return NOT_ENOUGH_FUZZ
            value = to_int(fuzzing_data)
            
        body[STREAM_DATA] = f"{value:0{b_size}b}"[-b_size:]
        return OK


    def _parse_payload(self, layer: dict, upper_layer: str):
        """
        Check if there is an encapsulated layer and set its pkt as the body;
        """
        if upper_layer:
            if PKT in self._protocols[upper_layer]: 
                layer[BODY][STREAM_DATA] = self._protocols[upper_layer][PKT]
            
        if not STREAM_DATA in layer[BODY] or not layer[BODY][STREAM_DATA]: 
            layer[BODY][STREAM_DATA] = ''
        layer[PKT] = layer[BODY][STREAM_DATA]
        return


    def _assemble_header(self, layer: dict, packet: bytes, upper_layer: str):
        """
        Assemble the header of a given protocol/layer into a binary file.

        Args:
            layer_id: A pointer to the layer's dictionary
            packet: The state of the packet up to now
            upper_layer: Identifier of the encapsulated layer
        """
        header = layer[HEADER]
        meta = layer[META]        
        # Group fields by type before evaluating them
        grouped = {T_NESTED : list(), T_CONDITION: list(), T_CONDITIONAL: list(),
                   T_DATA: list(), T_FUZZED: list(), T_POINTER: list(),
                   T_CHECKSUM: list(), T_HANDLER: list(), T_LENGTH: list(),
                   T_REFERENCE: list()}
        
        for name, field in header.items():
            if OPAQUE in field and field[OPAQUE]:
                self._opaque_field(field, layer, upper_layer)
                continue
            self._sort_fields(name, field, grouped)
            
        # First, deal with conditional fields
        for name, field in grouped[T_CONDITION]:
            # evaluate the condition first    
            if self._eval_condition(field, layer, upper_layer) == NOT_ENOUGH_FUZZ:
                return NOT_ENOUGH_FUZZ
            
        # Deal with nested fields
        # first do action nested fields, e.g., 6lowpan frag and compress header
        for name, field in grouped[T_NESTED]:
            if C_MASKED in field and field[C_MASKED] == True:
                continue
            if ACTION in field:
                continue
            if not ACTION in field and T_NESTED in field:
                nested_res = self._eval_nested(field, layer, upper_layer)
                if self._ran_out_of_fuzz:
                    return NOT_ENOUGH_FUZZ
                if not nested_res:
                    continue
            if self._assemble_header(field, b'', upper_layer) == NOT_ENOUGH_FUZZ:
                return NOT_ENOUGH_FUZZ
            
            field[STREAM_DATA] = field[PKT]
            field[SIZE] = field[META][HEADER_LEN] // 8 
            
        # assemble
        # has header been assembled previously
        # if not set pointers and length raw if static, else relative to other fields
        # also set meta entry of layer
        meta[HEADER_LEN],_ = self._calc_all_ptrs(header, meta)

        # evaluate using the grouping order
        for name, field in grouped[T_DATA]:
            self._eval_data(field, layer, upper_layer)

        for name, field in grouped[T_FUZZED]:
            if self._eval_fuzzed(field, layer, upper_layer) == NOT_ENOUGH_FUZZ:
                return NOT_ENOUGH_FUZZ

        for name, field in grouped[T_REFERENCE]:
            if self._eval_reference(field, layer, upper_layer) == NOT_ENOUGH_FUZZ:
                return NOT_ENOUGH_FUZZ

        for name, field in grouped[T_POINTER]:
            self._eval_pointer(field, layer, upper_layer)
        
        for name, field in grouped[T_CONDITIONAL]:
            if self._eval_conditional(field, layer, upper_layer) == NOT_ENOUGH_FUZZ:
                return NOT_ENOUGH_FUZZ
    
        for name, field in grouped[T_CHECKSUM]:
            self._set_zero(field, layer, upper_layer)
        
        for name, field in grouped[T_HANDLER]:
            if self._eval_handler(field, layer, upper_layer) == NOT_ENOUGH_FUZZ:
                return NOT_ENOUGH_FUZZ
        
        for name, field in grouped[T_LENGTH]:
            self._eval_length(field, layer, upper_layer)

        if self._perform_actions(grouped, layer, upper_layer) == NOT_ENOUGH_FUZZ:
            return NOT_ENOUGH_FUZZ

        for name, field in grouped[T_NESTED]:
            if C_MASKED in field and field[C_MASKED]:
                continue
            if not ACTION in field:
               continue
            if self._assemble_header(field, b'', '') == NOT_ENOUGH_FUZZ:
               return NOT_ENOUGH_FUZZ
            field[STREAM_DATA] = field[PKT]
            field[SIZE] = field[META][HEADER_LEN] // 8 

        # actively manipulate the packet before assmebly and evaling the checksum
        if self._introduce_faults(layer, upper_layer) == NOT_ENOUGH_FUZZ:
            return NOT_ENOUGH_FUZZ

        meta[HEADER_LEN],_ = self._calc_all_ptrs(header, meta)
        self._assemble_fields(layer)

        # check if there are any handlers in the handler queue; if there is no upper layer we are in a nested header
        # and dont want to execute the checksum (at least for now)
        if upper_layer or not packet:
            self._check_handler_queue(field, layer, upper_layer)
            
        for name, field in grouped[T_CHECKSUM]:
            self._eval_checksum(field, layer, upper_layer)

        return b''
    

    def _sort_fields(self, name: str, field: dict, grouped: dict):
        """ Sorting the fields by type and resetting/removing some values """
        if DOC in field:
            field.pop(DOC)
            
        if COMPRESSED in field:
            field[COMPRESSED] = False

        grouped[field[TYPE]].append((name, field))
        return


    def _perform_actions(self, grouped: dict, layer: dict, upper_layer: str):
        """ Perform handler based actions like compression. As they (may) modify the packet they are seperated from other handlers"""
        compressed = [x for x in grouped[T_NESTED] + grouped[T_HANDLER] if (ACTION in x[1] and A_COMPRESSION in x[1][ACTION])]
        fragmented = [x for x in grouped[T_NESTED] + grouped[T_HANDLER] if (ACTION in x[1] and A_FRAGMENTATION in x[1][ACTION])]

        # Compression
        for name, field in compressed:   
            if C_MASKED in field and field[C_MASKED]:
                continue
            comp_res = self._eval_handler_without_placing_data(field, layer, upper_layer)     
            if self._ran_out_of_fuzz:
                return NOT_ENOUGH_FUZZ

            #if comp_res and upper_layer not in self._waiting_fragments:
            if upper_layer not in self._waiting_fragments:
                # TODO use the target to also be able to compress upper layers. not only inligned headers   
                recompress_layer = layer[HEADER][field['target']]  #self._protocols[upper_layer] if upper_layer else dict()
                recompress_layer[META][UNCOMPRESSED_LEN] = recompress_layer[META][HEADER_LEN]
                recompress_layer[META][HEADER_LEN], _ = self._calc_all_ptrs(recompress_layer[HEADER], recompress_layer[META])
                self._assemble_fields(recompress_layer)
                recompress_layer[META][UNCOMPRESSED_LEN] = recompress_layer[META][HEADER_LEN]
                if recompress_layer[TYPE] == T_NESTED:
                    recompress_layer[STREAM_DATA] = recompress_layer[PKT]
                self._switch_endianess(recompress_layer)
                
            if name in [x[0] for x in grouped[T_HANDLER]]:
                grouped[T_HANDLER].pop([x[0] for x in grouped[T_HANDLER]].index(name))

        # Fragmentation
        for name, field in fragmented:
            # essentially, if this is the first fragment, we want the current header to be finished last
            # if this is a subsequent fragment, we know the length of the next higher layer, and already have the fragment length
            # calculated
            frag_res = self._eval_handler_without_placing_data(field, layer, upper_layer)
            if self._ran_out_of_fuzz:
                return NOT_ENOUGH_FUZZ
            
            if frag_res and upper_layer not in self._waiting_fragments:
                # store the fragments in the list and only continue with the most recent fragment.
                # This should allow us to still access values of the subsequent layer
                # We also need to store in the list, from which layer on we need to continue assembling
                # when take the next fragment
                layer[META][FRAGMENT_NR] = 0 
                tmp_fragments = list()
                for i in range(0, len(layer[BODY][STREAM_DATA]), frag_res):
                    if i + frag_res > len(layer[BODY][STREAM_DATA]):
                        tmp_fragments.append(layer[BODY][STREAM_DATA][i:len(layer[BODY][STREAM_DATA])])
                    else:
                        tmp_fragments.append(layer[BODY][STREAM_DATA][i:i+frag_res])
                if tmp_fragments:
                    self._waiting_fragments[upper_layer] = tmp_fragments

            if upper_layer in self._waiting_fragments:
                layer[BODY][STREAM_DATA] = self._waiting_fragments[upper_layer].pop(0)
                layer[META][FRAGMENT_NR] += 1
                if not self._waiting_fragments[upper_layer]:
                    # reset if no fragments left 
                    self._waiting_fragments.pop(upper_layer)
                    layer[META][FRAGMENT_NR] = 0

            if name in [x[0] for x in grouped[T_HANDLER]]:
                grouped[T_HANDLER].pop([x[0] for x in grouped[T_HANDLER]].index(name))  


    def _calc_all_ptrs(self, header: dict, meta: dict) -> int:
        """
        Calculate and set a pointer and length for each field entry.
        These can be used to write the bitstream later on.

        Returns:
            The added length of the entire header in bitwise granularity
        """
        # by now everything should be evaluatable; i.e., there are no conditions and no unknown nested headers
        length = 0
        uncompressed_length = 0
        for name, field in header.items():
            # conditionals evaluated before this; if not used set length to 0
            field[STREAM_POINTER] = length 
            if C_MASKED in field and field[C_MASKED] == True:
                continue 
            if field[TYPE] == T_NESTED:
                if not HEADER_LEN in field[META]:
                    continue
                # nested header
                field[STREAM_LEN] = field[META][HEADER_LEN]
            elif field[TYPE] == T_CONDITIONAL or field[TYPE] == T_CONDITION:
                field[STREAM_LEN] = get_bitsize(field)

            else:
                field[STREAM_LEN] = get_bitsize(field)

            uncompressed_length += field[STREAM_LEN]
            if COMPRESSED in field and field[COMPRESSED]:
                continue 
            length += field[STREAM_LEN]

        meta['dirty'] = 0
        return length, uncompressed_length


    def _opaque_field(self, field: dict, layer: dict, upper_layer: str):
        """ Set size of opaque field to zero so there is no pointer calculation for the bitstream """
        field[SIZE] = 0
        return
        

    def _introduce_faults(self, layer: dict, upper_layer: str):
        """
        At some points in the fuzzing process we may want to introduce faults into the assembled packets.
        The layer has already been decided, earlier, now we decided wether we introduce a fault and 
        if so which field of the layer is manuipulated.

        Args: 
            layer:          dict representation of the current layer
            upper_layer:    name of the next upper layer
        """
        if self._faulty_layer != resolve_protocol_id(layer[META][ID]) or self._faulty_layer == None:
            return

        # IF we are in the correct layer roll dice for probability
        dice = self._get_fuzz(1)
        if self._ran_out_of_fuzz:
            return NOT_ENOUGH_FUZZ

        dice = int.from_bytes(dice, "big")
        if self._fault_probability < ((dice * 100) // DICE_MAX):
            # No faults are introduced
            return
        
        # introduce fault 
        self._logger.error(f"Introducing fault in layer {resolve_protocol_id(layer[META][ID])}")
        header_fields = list(layer[HEADER].keys())
        prob_table = list()

        for field in header_fields:
            if (C_MASKED in layer[HEADER][field] and layer[HEADER][field][C_MASKED]) or (COMPRESSED in layer[HEADER][field] and layer[HEADER][field][COMPRESSED]):
                continue
            prob_table.extend([field] * weight_table[layer[HEADER][field][TYPE]])
        
        if len(prob_table) == 0:
            return OK
        
        # Add 10 percent probability to replace the entire layer with random input
        prob_table.extend(((len(prob_table)//10) +1) * ['nuke']) 
        
        # 10 percent probability to mutate a slice of the encapsulated layer
        if upper_layer:
            prob_table.extend(((len(prob_table)//10) +1) * ['slice'])

        # roll the dice which field to mutate, but first shuffle the table
        dice = self._get_fuzz(int(len(prob_table)/256) + (len(prob_table) % 256 > 0))
        if self._ran_out_of_fuzz:
            return NOT_ENOUGH_FUZZ
        field_dice = int.from_bytes(dice, "big") % len(prob_table)
        random.Random(self._consumed_fuzz[-2]).shuffle(prob_table)

        target = prob_table[field_dice] # target is the field we mutate/the action we take

        if target == "slice":
            upper_len = len(layer[BODY][STREAM_DATA])//8
            if not upper_len:
                return OK
            dice = self._get_fuzz(1)
            if self._ran_out_of_fuzz:
                return NOT_ENOUGH_FUZZ
            slice_dice = int.from_bytes(dice, "big")
            start = (slice_dice & 0xf) % upper_len
            stop = start + (slice_dice >> 4) % (upper_len - start)
            dice = self._get_fuzz(stop - start)
            if self._ran_out_of_fuzz:
                return NOT_ENOUGH_FUZZ
            splice = int.from_bytes(dice, "big")
            layer[BODY][STREAM_DATA] = layer[BODY][STREAM_DATA][:start*8] + f"{splice:0{((stop-start)*8)}b}" + layer[BODY][STREAM_DATA][stop*8:] 
            return OK

        if target == "nuke":
            self.nuke_layer = resolve_protocol_id(layer[META][ID])  
            return OK

        # nested case - i.e., target is a nested layer
        nested_case = ""
        if (layer[HEADER][target][TYPE] == T_NESTED):
            nested_case = target
            layer = layer[HEADER][target]
            nested_table = list()
            for field in (layer[HEADER].keys()):
                nested_table.extend([field] * weight_table[layer[HEADER][field][TYPE]])
            field_dice = ((int.from_bytes(dice, "big") >> 4) | ((int.from_bytes(dice, "big") << 4) & 0xff)) % len(nested_table)
            target = nested_table[field_dice]

        field = layer[HEADER][target]
        is_ephemeral = field[F_EPHEMERAL] if F_EPHEMERAL in field else False
        field[F_EPHEMERAL] = True
        
        if self._eval_fuzzed(field, layer, upper_layer) == NOT_ENOUGH_FUZZ:
            return NOT_ENOUGH_FUZZ
        if not is_ephemeral:
            field.pop(F_EPHEMERAL)

        if nested_case:
            # Reassemble in the nested case
            self._assemble_fields(layer)
            layer[STREAM_DATA] = layer[PKT]
            
        return OK


    def _entire_layer_fuzzed(self, layer: str):
        """ This nukes/overwrites an entire layer of a network packet. Part of the fault introduction """
        layer = self._protocols[layer]
        fuzzing_data = self._get_fuzz(layer[META][HEADER_LEN] // 8)
        if self._ran_out_of_fuzz:
            return NOT_ENOUGH_FUZZ
        overwrite = to_int(fuzzing_data)
        layer[PKT] = f"{overwrite:0{layer[META][HEADER_LEN]}b}"
        return OK


    def _eval_bitmask(self, field: dict, layer: dict, upper_layer: str):
        """ Evaluate a bitmask as a condition and mask/unmask the corresponding fields """
        conditional_fields = field[BITMASK] # list
        bitmask = field[STREAM_DATA]
        for index in range(len(conditional_fields)):
            if bitmask[index] == '0':
                layer[HEADER][conditional_fields[index]][C_MASKED] = True
            else:
                layer[HEADER][conditional_fields[index]][C_MASKED] = False
        
        return


    def _eval_data(self, field: dict, layer: dict, upper_layer: str):
        """ Given a dictionary representing a single field of the type data fill in the corresponding data """
        if not VALUE in field:
            self._logger.error(f"No value found in a data typed field"); exit(1)
        # make sure value is a) preceeded by correct number of leading zeros and b) not longer than allowed
        field[STREAM_DATA] = f"{place_data(field[VALUE], field[STREAM_LEN]):0{field[STREAM_LEN]}b}"[-field[STREAM_LEN]:]
        return
   

    def _eval_fuzzed(self, field: dict, layer: dict, upper_layer: str):
        """ Given a dictionary representing a single field of the type fuzzed fill in the corresponding data """
        if ((STREAM_DATA in field and F_EPHEMERAL not in field) or not get_bytesize(field)
            or (C_MASKED in field and field[C_MASKED])):
            # If field is not ephemeral and already contains data, we are done (or if masked)
            return OK

        if OPTIONS in field:
            # Pick one of the supplied options
            dice = self._get_fuzz(1)
            if self._ran_out_of_fuzz:
                return NOT_ENOUGH_FUZZ
            dice = to_int(dice) % len(field[OPTIONS])
            value = field[OPTIONS][dice]

            if value == -1:
                # option -1 -> fuzzed
                fuzzing_data = self._get_fuzz(get_bytesize(field))
                if self._ran_out_of_fuzz:
                    return NOT_ENOUGH_FUZZ
                value = to_int(fuzzing_data)

            stream_len_diff = 0
            if isinstance(value, str):
                if len(value) != get_bytesize(field):
                    field[SIZE] = len(value)
                    stream_len_diff = len(value) * 8 - field[STREAM_LEN]
                    field[STREAM_LEN] = len(value) * 8 
                value = int.from_bytes(value.encode("utf-8"), "big")
                
            if isinstance(value, bytes):
                if len(value) != get_bytesize(field):
                    field[SIZE] = len(value)
                    stream_len_diff = len(value) * 8 - field[STREAM_LEN]
                    field[STREAM_LEN] = len(value) * 8 
                value = int.from_bytes(value, "big")
            layer[META][HEADER_LEN] += stream_len_diff

        else:
            # 'regular' fuzzed
            fuzzing_data = self._get_fuzz(get_bytesize(field))
            if self._ran_out_of_fuzz:
                return NOT_ENOUGH_FUZZ
            value = to_int(fuzzing_data)

        field[VALUE] = value
        field[STREAM_DATA] = f"{value:0{field[STREAM_LEN]}b}"[-field[STREAM_LEN]:]
        return OK
    

    def _eval_handler_without_placing_data(self, field: dict, layer: dict, upper_layer: str):
        """ Evaluate handler without placing the received value as data is necessary for action-bound handlers for Fragmentation and compression """
        if not H_RESOLVED in field:
            # resolve handler if it has not been done yet
            if field[TYPE] == T_NESTED:
                resolve_handler(field, T_NESTED)
                handler = field[H_RESOLVED]
            if field[TYPE] == T_CONDITION:
                handler = resolve_handler(field, COND_HANDLER, store=False)
            if field[TYPE] == T_HANDLER:
                resolve_handler(field, HANDLER)
                handler = field[H_RESOLVED]
        else:
            handler = field[H_RESOLVED]

        upper_layer = self._protocols[upper_layer] if upper_layer else dict()
        # evaluate the handler
        value = handler(field, layer, upper_layer, self._get_fuzz) 
        return value


    def _eval_nested(self, field: dict, layer: dict, upper_layer: str):
        """ Given a dictionary representing a single field of the type nested fill in the corresponding data """
        if C_MASKED in field and field[C_MASKED]:
            return False
        if not H_RESOLVED in field:
            # resolve handler if it has not been done yet
            resolve_handler(field, T_NESTED)   

        handler = field[H_RESOLVED]
        upper_layer = self._protocols[upper_layer] if upper_layer else dict()
        # evaluate the handler
        value = handler(field, layer, upper_layer, self._get_fuzz) 
        return value


    def _eval_handler(self, field: dict, layer: dict, upper_layer: str):
        """ Given a dictionary representing a single field of the type handler fill in the corresponding data """
        if not H_RESOLVED in field:
            # resolve handler if it has not been done yet
            resolve_handler(field, HANDLER)

        handler = field[H_RESOLVED]
        upper_layer = self._protocols[upper_layer] if upper_layer else dict()

        # evaluate the handler
        value = handler(field, layer, upper_layer, self._get_fuzz) 
        if self._ran_out_of_fuzz:
            return NOT_ENOUGH_FUZZ
        field[STREAM_DATA] = f"{place_data(value, field[STREAM_LEN]):0{field[STREAM_LEN]}b}"[-field[STREAM_LEN]:]
        return OK
    

    def _eval_cond_handler(self, field: dict, layer: dict, upper_layer: str):
        """ Evaluate a condition handler """
        handler = resolve_handler(field, COND_HANDLER, store=False)
        upper_layer = self._protocols[upper_layer] if upper_layer else dict()
        # evaluate the handler
        value = handler(field, layer, upper_layer, self._get_fuzz) 
        return value
    

    def _eval_condition(self, field: dict, layer: dict, upper_layer: str):
        """ Given a dictionary representing a single field of the type condition fill in the corresponding data """
        field[C_MASKED] = False
        # as we do not know if we have calculated pointers and lens for the bitstream, do so first
        if not STREAM_LEN in field:
            field[STREAM_LEN] = get_bitsize(field)

        if not BITMASK in field:
            # the field is condition and conditional, i.e., its handler decides, whether the
            # field is used in the first place
            if not self._eval_cond_handler(field, layer, upper_layer):
                field[C_MASKED] = True
            if self._ran_out_of_fuzz:
                return NOT_ENOUGH_FUZZ
            return OK

        if HANDLER in field:
            if self._eval_handler(field, layer, upper_layer) == NOT_ENOUGH_FUZZ:
                return NOT_ENOUGH_FUZZ
        elif VALUE in field:
            self._eval_data(field, layer, upper_layer)
        else:
            if self._eval_fuzzed(field, layer, upper_layer) == NOT_ENOUGH_FUZZ:
                return NOT_ENOUGH_FUZZ
        
        self._eval_bitmask(field, layer, upper_layer)  
        return OK


    def _eval_pointer(self, field: dict, layer: dict, upper_layer: str):
        """ Given a dictionary representing a single field of the type pointer fill in the corresponding data """
        if not upper_layer:
            no_ptr = 0
            if DEFAULT in field:
                no_ptr = field[DEFAULT]
            elif VALUE in field:
                no_ptr = field[VALUE]
            field[VALUE] = no_ptr
            field[STREAM_DATA] = field[STREAM_DATA] = f"{no_ptr:0{field[STREAM_LEN]}b}"[-field[STREAM_LEN]:]
            return
        
        value = self._protocols[upper_layer][META][ID] & 0xffff
        field[VALUE] = value
        field[STREAM_DATA] = f"{place_data(value, field[STREAM_LEN]):0{field[STREAM_LEN]}b}"[-field[STREAM_LEN]:]
        return

    
    def _eval_length(self, field: dict, layer: dict, upper_layer: str):
        """ Given a dictionary representing a single field of the type length fill in the corresponding data """
        scope = field[L_SCOPE] if L_SCOPE in field else L_HEADER
        multiplier = multipliers[field[L_FORMAT]] if L_FORMAT in field else 1

        if scope == L_HEADER:
            length = layer[META][HEADER_LEN]
        elif scope == L_BODY:
            length = len(layer[PKT]) # TODO depending on payload assembly
        elif scope == L_EVERYTHING:
            length = layer[META][HEADER_LEN] + len(layer[PKT]) # TODO
        else:
            length = 0
            # allow scoping header fields for TLV
            if scope in layer[HEADER]:
                if SIZE in layer[HEADER][scope]:
                    length = layer[HEADER][scope][SIZE] * 8
                if META in layer[HEADER][scope]:
                    length = layer[HEADER][scope][HEADER_LEN] 

        if L_MODIFIER in field:
            length = length + (field[L_MODIFIER] * 8)
        # We assume a byte padded length for now
        if length % 8:
            self._logger.error(f"Length of {scope} is not byte aligned; potentially continuing with wrong values")
            pass

        value = (length // 8) // multiplier
        field[VALUE] = value
        field[STREAM_DATA] = f"{place_data(value, field[STREAM_LEN]):0{field[STREAM_LEN]}b}"[-field[STREAM_LEN]:]
        return


    def _eval_checksum(self, field: dict, layer: dict, upper_layer: str):
        """ Given a dictionary representing a single field of the type checksum fill in the corresponding data. Additionally, update the overall pkt """
        if not H_RESOLVED in field:
            # resolve handler if it has not been done yet
            resolve_checksum(field, CHECKSUM)

        handler = field[H_RESOLVED]
        upper_layer = self._protocols[upper_layer] if upper_layer else dict()

        # evaluate the handler
        value = handler(field, layer, upper_layer) 
        if type(value) == str:
            value = 0
            self._handler_queue.append(handler)

        field[STREAM_DATA] = f"{place_data(value, field[STREAM_LEN]):0{field[STREAM_LEN]}b}"[-field[STREAM_LEN]:]
        self._paket_insert(field, layer)
        return
    

    def _eval_conditional(self, field: dict, layer: dict, upper_layer: dict):
        """ Given a dictionary representing a single field of the type conditional fill in the corresponding data. """
        if field[C_MASKED]:
            return OK
        # So far coniditonal only allows for handler, value , fuzzed
        if HANDLER in field:
            if self._eval_handler(field, layer, upper_layer) == NOT_ENOUGH_FUZZ:
                return NOT_ENOUGH_FUZZ
        elif VALUE in field:
            self._eval_data(field, layer, upper_layer)
        else:
            if self._eval_fuzzed(field, layer, upper_layer) == NOT_ENOUGH_FUZZ:
                return NOT_ENOUGH_FUZZ

        return OK


    def _eval_reference(self, field: dict, layer: dict, upper_layer: dict):
        """ Given a dictionary representing a single field of the type reference fill in the corresponding data. """
        if not type(field[REFERENCE]) == str:
            exit(1) # this should never happen, TODO more elegant handling

        if C_MASKED in field and field[C_MASKED]:
            return OK

        protocol, target_field = field[REFERENCE].split('.')
        if protocol not in self._protocols and not (STREAM_DATA in field or VALUE in field):
            # eg. TCPIP, BLE, IEEE802154
            if field[REFERENCE] not in self._apriori_knowledge:
                if self._eval_fuzzed(field, layer, upper_layer) == NOT_ENOUGH_FUZZ:
                    return NOT_ENOUGH_FUZZ

                self._apriori_knowledge[field[REFERENCE]] = field[VALUE]
                return OK

            field[VALUE] = self._apriori_knowledge[field[REFERENCE]]
            field[STREAM_DATA] = f"{place_data(self._apriori_knowledge[field[REFERENCE]], field[STREAM_LEN]):0{field[STREAM_LEN]}b}"[-field[STREAM_LEN]:]
            return OK        

        if STREAM_DATA in field:
            value = int(field[STREAM_DATA], 2)
        elif VALUE in field:
            value = field[VALUE]
        elif DEFAULT in field:
            value = field[DEFAULT]
        else:
            if self._eval_fuzzed(field, layer, upper_layer) == NOT_ENOUGH_FUZZ:
                return NOT_ENOUGH_FUZZ
            return OK

        field[STREAM_DATA] = f"{place_data(value, field[STREAM_LEN]):0{field[STREAM_LEN]}b}"[-field[STREAM_LEN]:]
        return OK


    def _check_handler_queue(self, field: dict, layer: dict, upper_layer: str):
        """ Check if there are handlers waiting to be executed in the handler queue (e.g., a tcp checksum).
            We need a handler queue, because some fields need information of the lower layers.
            For example, transport layer checksums that require an IPv4 pseudo header
        """
        if len(self._handler_queue) == 0:
            return

        upper_layer = self._protocols[upper_layer] if upper_layer else dict()
        new_list = list()
        for handler in self._handler_queue:
            res = handler(field, layer, upper_layer)
            if isinstance(res, str):
                new_list.append(handler)

        if len(self._handler_queue) == len(new_list):
            self._handler_queue = new_list
            return
        self._handler_queue = new_list

        if PKT in upper_layer:
            pre_assembly = upper_layer[PKT]
            self._assemble_fields(upper_layer)
            if pre_assembly != upper_layer[PKT]:
                if not BODY in layer:
                    layer[BODY] = {STREAM_DATA: upper_layer[PKT]}
                else:
                    # something changed. Reassemble the current layer as well
                    layer[BODY][STREAM_DATA] = upper_layer[PKT]
                    self._assemble_fields(layer)

        return


    def _set_zero(self, field: dict, layer: dict, upper_layer: str):
        """ Zero out a given field. Usually a temporary measure for checksum fields. """
        value = 0
        field[STREAM_DATA] = f"{value:0{field[STREAM_LEN]}b}"[-field[STREAM_LEN]:]
        return

    
    def _assemble_fields_no_compression(self, layer: dict):
        """ DEBUG only for compression """
        if HEADER_LEN not in layer[META] or not layer[META][HEADER_LEN]:
            return
        
        if UNCOMPRESSED_LEN in layer[META] and layer[META][UNCOMPRESSED_LEN] != layer[META][HEADER_LEN]:
            # we need to cut pkt as it was compressed already
            layer[PKT] = layer[PKT][layer[META][UNCOMPRESSED_LEN]:]

        body_len = len(layer[BODY][STREAM_DATA]) if (BODY in layer and STREAM_DATA in layer[BODY]) else 0
        layer[PKT] = layer[META][HEADER_LEN] * '0' + layer[BODY][STREAM_DATA] if body_len else layer[META][HEADER_LEN] * '0' 

        for name, field in layer[HEADER].items():
            if ((C_MASKED in field and field[C_MASKED])):
                continue
            if field[SIZE] == 0:
                continue

            self._paket_insert(field, layer)

        if len(layer[PKT]) > layer[META][HEADER_LEN] + body_len:
            self._logger.error("[!] paket assembly went horribly wrong?!"); exit(1)

        return


    def _assemble_fields(self, layer: dict):
        """ Assemble data from all fields (incl. body) into a single packet. Which is placed in the layers dict """
        if HEADER_LEN not in layer[META] or not layer[META][HEADER_LEN]:
            return
        
        if UNCOMPRESSED_LEN in layer[META] and layer[META][UNCOMPRESSED_LEN] != layer[META][HEADER_LEN]:
            # we need to cut pkt as it was compressed already
            layer[PKT] = layer[PKT][layer[META][UNCOMPRESSED_LEN]:]

        body_len = len(layer[BODY][STREAM_DATA]) if (BODY in layer and STREAM_DATA in layer[BODY]) else 0
        layer[PKT] = layer[META][HEADER_LEN] * '0' + layer[BODY][STREAM_DATA] if body_len else layer[META][HEADER_LEN] * '0' 

        for name, field in layer[HEADER].items():
            if ((C_MASKED in field and field[C_MASKED]) or (COMPRESSED in field and field[COMPRESSED])):
                continue
            if field[SIZE] == 0:
                continue
            if field[TYPE] == T_NESTED:
                pass

            self._paket_insert(field, layer)

        if len(layer[PKT]) > layer[META][HEADER_LEN] + body_len:
            # sanity check
            self._logger.error("[!] paket assembly went wrong?!"); exit(1)

        return

    
    def _paket_insert(self, field: dict, layer: dict) -> str:
        """ Insert data into the layers packet stream, after it has already been assembled. Necessary for checksums """
        pkt = layer[PKT]
        layer[PKT] = pkt[:field[STREAM_POINTER]] + field[STREAM_DATA][:field[STREAM_LEN]] + pkt[(field[STREAM_POINTER] + field[STREAM_LEN]):]
        return pkt
    

    def protocol_specific_changes(self, packet: list):
        """ For some protocols, we want to change/add apriori values in a fuzzer-driven manner """
        if "Ethernet" in packet:
            # We want to switch between broad/multi/unicast
            if self._consumed_fuzz:
                dice = self._consumed_fuzz[-1] ^ 0xffffffff
            else:
                dice = self._get_fuzz(1)
                if self._ran_out_of_fuzz:
                    return NOT_ENOUGH_FUZZ
                dice = int.from_bytes(dice, "big")

            if dice % 10 == 1:
                self._apriori_knowledge["TCPIP.MAC_dest"] = 0xffffffffffff

        if "IGMP" in packet:
            # Address with IGMP should be multicast
            if "TCPIP.IP4_dest" in self._apriori_knowledge:
                self._apriori_knowledge["TCPIP.IP4_dest"] = 0xe0000000 | (self._apriori_knowledge["TCPIP.IP4_dest"] & 0xffffff)
            else:
                self._apriori_knowledge["TCPIP.IP4_dest"] = 0xe0000000

        if "ICMP4" in packet:
            # We want to switch between broad/multi/unicast
            if self._consumed_fuzz:
                dice = self._consumed_fuzz[-1] ^ 0xffffffff
            else:
                dice = self._get_fuzz(1)
                if self._ran_out_of_fuzz:
                    return NOT_ENOUGH_FUZZ
                dice = int.from_bytes(dice, "big")

            if dice % 3 == 0:
                # leave everything be
                pass
            elif dice % 3 == 1:
                # multicast
                if "TCPIP.IP4_dest" in self._apriori_knowledge:
                    self._apriori_knowledge["TCPIP.IP4_dest"] = 0xe0000000 | (self._apriori_knowledge["TCPIP.IP4_dest"] & 0xffffff)
                else:
                    self._apriori_knowledge["TCPIP.IP4_dest"] = 0xe0000000

            elif dice % 3 == 2:
                # broadcast
                if "TCPIP.IP4_dest" in self._apriori_knowledge:
                    if dice % 2 == 0:
                        self._apriori_knowledge["TCPIP.IP4_dest"] = 0xffffffff
                    else:
                        self._apriori_knowledge["TCPIP.IP4_dest"] = self._apriori_knowledge["TCPIP.IP4_dest"] | 0xff

                else:
                    self._apriori_knowledge["TCPIP.IP4_dest"] = 0xffffffff

        if 'ARP' in packet:
            if self._consumed_fuzz:
                dice = self._consumed_fuzz[-1] ^ 0xffffffff
            else:
                dice = self._get_fuzz(1)
                if self._ran_out_of_fuzz:
                    return NOT_ENOUGH_FUZZ
                dice = int.from_bytes(dice, "big")

            if dice % 2 == 0:
                pass
            elif dice % 2 == 1:
                self._protocols['ARP'][HEADER]['operation'][VALUE] = 1
                self._protocols['ARP'][HEADER]['tha'][VALUE] = 0xffffffffffff
        if '6lowpan_MAC_Data' in packet or '6lowpan_MAC_Beacon' in packet or '6lowpan_MAC_Command' in packet:
            if self._consumed_fuzz:
                dice = self._consumed_fuzz[-1] ^ 0xffffffff
            else:
                dice = self._get_fuzz(1)
                if self._ran_out_of_fuzz:
                    return NOT_ENOUGH_FUZZ
                dice = int.from_bytes(dice, "big")

            if dice % 4 == 0:
                pass
            elif dice % 4 == 1:
                self._apriori_knowledge['IEEE802154.PAN_dest'] = 0xffff
            elif dice % 4 == 2:
                self._apriori_knowledge['IEEE802154.LL_dest'] = 0xffff
            elif dice % 4 == 3:
                self._apriori_knowledge['IEEE802154.PAN_dest'] = 0xffff
                self._apriori_knowledge['IEEE802154.LL_dest'] = 0xffff

        return OK
