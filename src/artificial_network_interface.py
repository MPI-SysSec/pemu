# TODO imports
from .utils import *
from .packer import Packer
from .packet_parser import PacketParser
from .plugin_api import APIGadget
import copy
import uuid

# Analysis might fail if the destination addresses are left empty.
# For this case we use addresses that can be interpreted as multi or broadcasts by the receiver
default_analysis_values = {'TCPIP.MAC_dest': 0xffffffffffff, 'TCPIP.IP4_dest': 0xffffffff}
EPHEMERAL_ATTR_NAMES = [
    "_tree_init", "_logger", "_snapshot", "_all_packets", "_network_tree", "_protocol_state", "_probe_mode", "_current_reception_state"
]
SNAPSHOTTABLE_ATTR_NAMES = [
    "_packer", "_parser"
]


class ANI:
    """
    This class represents the the entire network from the emulators perspective. It is responsible for
    providing packets, which can be passed to the firmware through a peripheral. It also parses packets
    the firmware is transmitting, to gain knowledge on context specific values.
    """
    _packer: Packer
    _parser: PacketParser
    _protocol_state: list
    _cur_protocol_state: int # pointer to the list

    _tree_init: dict
    _network_tree: Tree
    _all_packets: list
    _logger: logging
    _get_bytes: types.FunctionType
    _probe_mode: bool
    _output_file: str
    _sent_packets: int
    _packet_log: list
    _snapshot = dict()

    _inject_faults: bool
    _np_only: bool
    _no_parse: bool
    _static: bool
    _packets_requested: int
    _current_reception_state: dict

    def __init__(self, in_config: dict, get_bytes: types.FunctionType, location: str, output_file: str=None, log_level=logging.WARNING):
        """
        Initialize ANI object
        """
        config = in_config
        if isinstance(config, str):
            # We not always receive a dict (e.g., if we are being called from Rust code)
            config = load_config_from_str(config)
            for key in list(config.keys()):
                if config[key] == None:
                    config.pop(key)
            if 'apriori' in config:
                tmp_apriori = dict()
                for list_item in config['apriori']:
                    key = list_item['field']
                    val = list_item['val']
                    tmp_apriori[key] = val
                config['apriori'] = tmp_apriori

        if self._check_mockup(config):
            return

        # Set default values
        logging.basicConfig()
        self._tree_init = {'Ethernet': tcpip_init, 'IEEE802154_PHY': sixlowpan_init, 'BLE_PHY': ble_init, 'Modbus': modbus_init}
        self._network_tree = None
        self._logger = logging.getLogger(self.__class__.__name__)
        self._logger.setLevel(log_level)
        self._output_file = f"{output_file}" if output_file else None
        self._probe_mode = False
        self._inject_faults = False
        self._zero_only = False
        self._static = True
        self._packets_requested = 0
        self._np_only = False
        self._no_parse = False
        self._static = False
        self._current_reception_state = dict()
        self._sent_packets = 0
        self._packet_log = list()

        self._parse_config(config)
        set_import_loc(location)

        if isinstance(get_bytes, str):
            self._gadget = plugin_api.APIGadget()
            self._get_bytes = getattr(self._gadget, get_bytes)
        else:
            self._gadget = APIGadget()
            self._get_bytes = get_bytes

        self._packer = Packer(config, self._protocol_state, self._get_bytes, log_level)
        self._parser = PacketParser(config, self._protocol_state, self._output_file, not self._static, log_level) # TODO add args if necessary
        self._init_network_tree()
        self._all_packets = self._init_all_packets(self._network_tree, [])
        if not self._output_file:
            self._no_parse = True

        return
    
    

    def rust_test(self):
        """
        Testing for Rust-based setups
        """
        test = self._get_bytes(4)
        return test

    def _check_mockup(self, config):
        """
        If there is no network configuration, we do not want to initialize everything, as it will be costly to snapshot and restore
        """
        if not config: 
            # Setup mockup functions
            self.get_packet = lambda *args, **kwargs: None
            self.parse_packet = lambda *args, **kwargs: None
            self.take_snapshot = lambda *args, **kwargs: None
            self.restore_snapshot = lambda *args, **kwargs: None
            self.discard_snapshot = lambda *args, **kwargs: None
            self.set_probe_mode = lambda *args, **kwargs: None

            return True

        return False

    def take_snapshot(self):
        """
        Take snapshot of all non ephemeral attributes and snapshottable items
        """
        for attr_name, value in self.__dict__.items():
            if attr_name in EPHEMERAL_ATTR_NAMES:
                continue
            
            if attr_name in SNAPSHOTTABLE_ATTR_NAMES:
                self._snapshot[attr_name] = getattr(self, attr_name)
                self._snapshot[attr_name].take_snapshot()
                continue
            
            self._snapshot[attr_name] = getattr(self, copy.deepcopy(attr_name))
        return
    
    def restore_snapshot(self):
        """
        Restore snapshot of all non ephemeral attributes and snapshottable items
        """
        for attr_name, val in self._snapshot.items():
            if attr_name in SNAPSHOTTABLE_ATTR_NAMES:
                self._snapshot[attr_name].restore_snapshot()
                continue
            if attr_name == '_gadget':
                continue
            
            setattr(self, attr_name, copy.deepcopy(self._snapshot[attr_name]))
        self._packet_log = list()
        return

    def discard_snapshot(self):
        """
        Discard snapshot
        """
        pass

    def _switch_to_true_randomness(self):
        """
        In probing mode we want to be able to switch to real randomness, to not drain the fuzzing input
        """
        self._get_bytes = os.urandom
        return

    def _parse_config(self, config: dict):
        """
        Parse the network configuration
        """
        if not config:
            config = dict()
        self._cur_protocol_state = 0
        if 'probe' in config and config['probe'] == True:
            self._probe_mode = True
            self._no_parse = True
            self._np_only = True
            if 'faults' in config:
                config.pop('faults')

        if 'faults' in config and 'probability' in config['faults']  and config['faults']['probability'] > 0:
            self._inject_faults = True

        self._increase_probe_depth = False
        if 'probe2' in config:
            if isinstance(config['probe2'], bool):
                self._increase_probe_depth = True
            elif isinstance(config['probe2'], str):
                if config['probe2'] == 'true':
                    # Necessary for the hoedru integration
                    self._increase_probe_depth = True
                elif config['probe2'] == 'ANALYSIS':
                    self._probe_mode = False
                    self._zero_only = True
                    self._no_parse = False
                else:
                    self._network_tree = self._tree_init[config['probe2']]() if config['probe2'] in self._tree_init else None

        if self._probe_mode:
            self.set_analysis_values(config)

        if 'analysis' in config:
            self._static = False

        if 'analysis' in config and config['analysis'] == False:
            self._static = True

        if 'np_only' in config:
            for key in list(config.keys()):
                if config[key] == None:
                    config.pop(key)
            self._np_only = True

        if  'protocols' not in config: 
            self._protocol_state = list() 
            self._packer = None
            self._parser = None  
            return
        

        self._logger.debug("initialyzing everything")
        if isinstance(config['protocols'], dict):
            self._protocol_state = [packet for name, packet in config['protocols'].items()] # string representation
        if isinstance(config['protocols'], list):
            self._protocol_state = list()
            for i in range(len(config['protocols'])):
                self._protocol_state.append(config["protocols"][i][next(iter(config["protocols"][i]))])
            
        self._logger.debug(self._protocol_state)
        return

    def log_receive(self):
        """
        We need to be able to log receives, for setups (namely hoedur) where we can not consume fuzzing input
        directly from the fuzzer, but need to proxy it through an APIGadget
        """
        if not self._static and self._gadget.get_input_id() != 0:
            # We used to do this by writing to a file: However we can also use a class variable, which we do not restore on snapshot restores
            if 'last_receive' not in self._current_reception_state or len(self._current_reception_state['last_receive']) > 2000:
                self._current_reception_state['last_receive'] = list()

            self._current_reception_state['last_receive'].append(self._gadget.get_input_id())

            if self._packets_requested < 2:
                if 'num_receives' in self._current_reception_state:
                    self._current_reception_state['num_receives'] = self._current_reception_state['num_receives'] + 1
                else:
                    self._current_reception_state['num_receives'] = 1
                if not self._static:
                    if not self._protocol_state:
                        if self._current_reception_state['num_receives'] > 2000:
                            self._gadget.set_inspect_results(True)
        return


    def set_analysis_values(self, config: dict):
        """
        For analysis we often want some default values. For example, broadcast addresses
        """
        if not 'apriori' in config:
            config['apriori'] = default_analysis_values
            return
        
        for key, val in default_analysis_values.items():
            if key in config['apriori']:
                continue
            config['apriori'][key] = val
        
        return

    def set_output_file(self, output_file):
        """
        Set the file to which the output is written
        """
        self._output_file = output_file
        self._parser.set_output_file(output_file)
        if output_file != None:
            self._no_parse = False
        return

    def set_probe_mode(self, mode: bool):
        """
        Set the probing mode
        """
        self._probe_mode = mode
        return

    def _init_network_tree(self):
        """
        Initialize the network tree. Part of the overall initializition
        """
        if self._network_tree:
            return

        if self._protocol_state:
            self._network_tree = self._tree_init[self._protocol_state[0][0]]()
            return

        self._network_tree = Tree("root")
        self._network_tree.set_children([tcpip_init(), sixlowpan_init(), ble_init()])
        return



    def get_packet(self, max_n=1) -> bytes:
        """
        Evaluate the current protocol state and return the according packet.
        Adjust the pointer to the current protocol order accordingly
        """
        self._packets_requested += 1
        if self._zero_only:
            return b''
            self._packer._switch_to_zero_randomness()

        if not self._protocol_state and not self._probe_mode:
            # no intial information on used protocol, send fuzzed packet, maybe add configuration option?
            packet = max_n * b'\x00'
            self._gadget.set_packet(packet)
            self.log_receive()
            return packet

        if not self._protocol_state and self._probe_mode:
            # this means first packet
            # we switch randomness to not drain the fuzzing input and alter the run mmio wise
            self._packer._switch_to_zero_randomness()
            self._switch_to_true_randomness()
            self._protocol_state.append(self._fuzzed_packet())
            self._write_probe_file(self._protocol_state[-1])
            self._probe_mode = False

        # npfuzz--
        if not self._probe_mode and not self._np_only:
            dice = self._get_bytes(1)

            if not dice:
                return []
            if int.from_bytes(dice, "big") % 2 == 1:
                self._gadget.set_random()
                return self._get_bytes(max_n)
                packet = self._get_bytes(int.from_bytes(dice, "big") % max_n)
                if not packet:
                    return []
                self._gadget.set_packet(packet)
                self.log_receive()
                return packet

        # npfuzz++
        cur_packet_config = list(self._protocol_state[self._cur_protocol_state])

        # TODO sometimes  packet if last layer is not a leaf node
        # In addtion to injecting faults, we 
        # a) want to append additional layers if the current last layer is not a leaf node
        # b) change the last layer to other equal protocols (UDP <-> ICMP <-> TCP) or (BLE advertisement channel packets)
        # c) nothing


        if (not self._probe_mode and self._inject_faults and 
            not is_leaf(self._network_tree, cur_packet_config[-1]) and not self._packer.has_fragments_waiting()):
            self._logger.debug(f"checking mutations")
            
            dice = self._get_bytes(1)
            if not dice:
                return b''
            dice = int.from_bytes(dice, "big")
            if dice % 3 == 0:
                # A)
                leaf = self._network_tree.find_node(cur_packet_config[-1])
                leaf_dice = (dice >> 2) % (len(leaf.get_children()) + 1)
                additional_layer = [leaf.get_children()[leaf_dice].get_name()] if leaf_dice < len(leaf.get_children()) else []
                cur_packet_config.extend(additional_layer)
                self._logger.debug(f"STAT-ADDITIONAL: {','.join([x for x in cur_packet_config])}")
            elif dice % 3 == 1:
                # B)
                parent = self._network_tree.find_node(cur_packet_config[-2]) if len(cur_packet_config) > 1 else None                
                if parent:
                    parent_dice = (dice >> 2) % (len(parent.get_children()))
                    cur_packet_config[-1] = parent.get_children()[parent_dice].get_name()
                    self._logger.debug(f"STAT-CHANGE: {','.join([x for x in cur_packet_config])}")
            else:
                pass
                self._logger.debug("STAT-NOTHING")



            
        packet = self._packer.get_packet(cur_packet_config)
        #print(f"ANI: packet is {cur_packet_config}:::{packet}")
        #import binascii
        #print(f"ANI: packet is {cur_packet_config}:::{binascii.hexlify(packet)}")
        if not packet:
            # Not enough fuzz!
            # we want to keep the packet pointer and return
            self._packets_requested -= 1
            self._gadget.set_packet(b'')
            return b''

        self._packet_log.append(remove_trailing_zeroes(packet))
        self._sent_packets += 1
        if self._packer.has_fragments_waiting():
        
            # fragmentation was used, ergo we should not change the packet and instead resend it until all fragments are transmitted
            self.log_receive()
            self._gadget.set_packet(packet)
            return packet

        if len(self._protocol_state) > self._cur_protocol_state + 1: # and not self._packer.has_fragments_waiting():
            # move on to the next packet
            self._cur_protocol_state += 1
        else:
            # if no further packets are given, we either just sent the same next time
            # or if in probe mode, add a random packet

            if self._probe_mode:
                self._packer._switch_to_zero_randomness()
                self._switch_to_true_randomness()
                self._protocol_state.append(self._fuzzed_packet())
                self._cur_protocol_state += 1
                self._write_probe_file(self._protocol_state[-1])
                self._probe_mode = False


        self.log_receive()

        self._gadget.set_packet(packet)
        return packet

    def parse_packet(self, packet: bytes, channel=-1) -> bool:
        """
        Parse a firmware tansmitted packet
        """
        if self._no_parse:
            return False

        if isinstance(packet, list):
            packet = bytearray(packet) 

        # Don't parse if packet was already parsed, not protocol state exists or we are in probe mode
        if (remove_trailing_zeroes(packet) in self._packet_log) or (not self._protocol_state) or self._probe_mode:
            self._logger.debug("Already sent the  exact same packet we received; discarding it")
            return False
        self._packet_log.append(remove_trailing_zeroes(packet))

        answer_to = self._cur_protocol_state - 1 if self._cur_protocol_state > 0 else self._cur_protocol_state
        if channel == -1:
            # Try to get the channel though the APIGadget
            channel = self._gadget.consume_channel()
        
        request_inspection = self._parser.parse_packet(packet, self._protocol_state[answer_to], self._sent_packets, self._network_tree, channel)

        # If we got new info we can request analysis through the APIGadget if the underlying rehosting system uses it
        if not self._static:
            self._gadget.set_inspect_results(request_inspection)
        return True

    def _write_probe_file(self, probe: list):
        """
        Write probing result to the output file
        """
        save_config({'probe': probe}, self._output_file)
        return


    def _fuzzed_packet(self) -> list:
        """
        Generate a random packlet configuration
        """
        dice = self._get_bytes(1)
        if not dice:
            return []
        dice = int.from_bytes(dice, "little") 

        if self._network_tree._data != "root":
            search_tree = self._all_packets
            
        else:
            base = self._network_tree.get_children()[dice % len(self._network_tree.get_children())]._data
            if self._increase_probe_depth:
                search_tree = [x for x in self._all_packets if x[0] == base and ((len(x) == 2 and x[0] == "Ethernet") or (len(x) == 3 and x[0] == "BLE_PHY") or (len(x) == 4 and x[0] == "IEEE802154_PHY"))]
            else:
                search_tree = [x for x in self._all_packets if x[0] == base and ((len(x) == 1 and x[0] == "Ethernet") or (len(x) == 2 and x[0] != "Ethernet"))]

        return search_tree[dice % len(search_tree)]


    def _init_all_packets(self, tree: Tree, state: list) -> list:
        """
        Calculate all possible packets for the current tree. 
        This gives all packets configs the same possibility to be chosen
        """
        data = []
        res = []
        if tree._data != "root":
            data = [tree._data]
            res = [state + data]
    
        for child in tree.get_children():
            tmp = list()
            if child._chain_next_one:
                tmp = [child._data]
                child = child.get_children()[0]
            res.extend(self._init_all_packets(child, state + data + tmp))

        return res

