import uuid


class CommunicatorInterface():
    _run_to_trace: list
    _run_id: int
    _input_file: str

    def __init__(self):
        self._run_to_trace = list()
        self._run_id = 0

        return

    def __exit__(self, exc_type, exc_value, exc_traceback):
        """
        Clean up on exit
        """
        import os
        for run_id, bb_file in self._run_to_trace:
            os.remove(bb_file)

        if self._input_file:
            os.remove(self._input_file)

        return

    def run_target(self, config_file: str, queue_in: str):
        """
        Run a specific target and create a uniquely named coverage trace file or a coverage list.
        The arguments represent minimal requirements. If more information is needed extend this 
        function accordingly.

        Args:
            config_file:    Path to the configuration file
            queue_in:       Path to the input
        """

        return
    
    def parse_trace(self) -> list:
        """
        Extract the trace of the oldest run, using the run_to_trace list.

        Returns:
            A list of integers, which represents the basic block coverage.
        """

        return []
    
    def enable_probe_mode(self, config_map: dict, config_path: str) -> str:
        """
        Enable the probe mode of the Artificial Network Interface. This usually happens when
        setting up the emulation environment from the config. 
        
        Args:
            config_map:     Dict containing the current config
            config_path:    Path to the current mains config file

        Returns:
            Path to the modified configuration file
        """

        return ""
    
    def extract_outputs(self, output_dir: str) -> list:
        """
        As the indivdual platform is resposible for supplying an output file path, it is also the platforms
        responsibility to open the output files and extract the contents.

        Params:
            output_dir: In almost all cases this function needs the path to a directory, from which it can extract the outputs

        Returns:
            Returns a list of the following structure: [(output_file_name_1: str, output: dict)]
        """

        return []
    
    def get_config_field(self, config_map: dict) -> dict:
        """
        As the analysis does not know how the config is structured, this functions allows the analysis part to access
        different fields of the *network*-related part of the config file.

        Args:
            config_map: The configuration. In the easiest case, this is only the network part.

        Returns:
            The network part of the configuration. I.e., {network: { ... }}
        """
        return{}
    
    def trim_input(self, input: str, config_map: dict) -> str:
        """
        When the platform logs the output (and pointers to the input) of the network packets,
        we can remove all the bytes from the input, that relate to packets we might replace with the analysis.
        If the fuzzing platform does not offer such capabilities, the original input is simply returned.

        Args:
            input:          Path to the input used for analysis
            config_map:     Dictionary containing the current configuration

        Returns:
            Path of the (potentially) modified input
        """
        return input
    
    def best_input_from_outputs(self, outputs: list) -> str:
        """
        In some cases, we can derive a good input from the output data as well.
        This can be circumvented by directly supplying and input to the analysis.

        Args:
            outputs:    List containing tuples of filename and output information about packets

        Returns:
            A path to the best possible input.
        """
        return


  
class FuzzwareCommunicator(CommunicatorInterface):
    _probe_output_file: str
    _probe_mode: bool
    _prefix_input: bool

    def __init__(self, config_map: dict, config_path: str):
        """
        Inititalize the FuzzwareCommunicator module.

        Args:
            config_map:
            config_path:    Path to the current configuration file
        """
        self._probe_output_file = f"/tmp/.output_test.yml_{uuid.uuid4()}"
        self._probe_mode = False
        self._prefix_input = False
        if 'boot' in config_map:
            self._prefix_input = True
        super().__init__()

    def run_target(self, config_file: str, queue_in: str, ram_trace:str=""):
        from fuzzware_pipeline.run_target import run_target
        import subprocess
        extra_args = list()
        if self._prefix_input:
            prefix_path = '/'.join(config_file.split('/')[:-1]) + '/prefix_input'
            extra_args = ['--prefix-input', prefix_path]

        if ram_trace:
            bb_file = f'{ram_trace}_bb'
            dma_file = f'{ram_trace}_dma'
            extra_args.extend(['--ram-trace-out', ram_trace, '--dma-trace-out', dma_file, '--bb-trace-out', bb_file])

        else:
            bb_file = f'{queue_in}_{self._run_id}'
            extra_args.extend(['--bb-trace-out', bb_file, '--dma-trace-out', f"{self._probe_output_file}_{self._run_id}"])

            self._run_to_trace.append((self._run_id, bb_file))
            self._run_id += 1
        
        # Use fuzzwares ready-to-use run_target function
        return run_target(config_file, queue_in, extra_args, silent=True, stdout=subprocess.DEVNULL)

    def parse_trace(self):
        from fuzzware_harness.tracing.serialization import parse_bbl_trace
        import os

        # uses fuzzwares built in functionality
        run_id, bb_file = self._run_to_trace.pop()
        bbl_trace = [x[1] for x in parse_bbl_trace(bb_file)]
        # clean up
        os.remove(bb_file)

        return bbl_trace
    
    def disable_probe_mode(self):
        self._probe_mode = False


    def np_only_config(self, config_map: dict, config_path: str) -> str:
        if not 'peripherals' in config_map:
            return ""
        
        from copy import deepcopy
        from fuzzware_pipeline.util.config import save_config
        import os
        new_config_path = "/".join(config_path.split('/')[:-1]) + "/.np_only_config.yml"
        if os.path.exists(new_config_path):
            return ""


        new_config_map = deepcopy(config_map)
        for x,y in new_config_map['peripherals'].items():
            if 'network' in y and y['network'] == None:
                y['network'] = dict()   

        protocol_enabled_periph = [y['network'] for x,y in new_config_map['peripherals'].items() if 'network' in y][0]
        protocol_enabled_periph['np_only'] = True


        save_config(new_config_map, new_config_path)
        return new_config_path

    def enable_probe_mode(self, config_map: dict, config_path: str, additional_info: int) -> str:
        if not 'peripherals' in config_map:
            return ""
        
        from copy import deepcopy
        from fuzzware_pipeline.util.config import save_config
        import os
        self._probe_mode = True
        new_config_map = deepcopy(config_map)
        for x,y in new_config_map['peripherals'].items():
            if 'network' in y and y['network'] == None:
                y['network'] = dict()   

        print([y['network'] for x,y in new_config_map['peripherals'].items() if 'network' in y])
        protocol_enabled_periph = [y['network'] for x,y in new_config_map['peripherals'].items() if 'network' in y][0]
        protocol_enabled_periph['probe'] = True
        if additional_info == 1: # RETRY
            protocol_enabled_periph['probe2'] = True
        elif additional_info == 2: # FIRST_TIME_RES_FOUND
            orig_protocol_enabled_periph = [y['network'] for x,y in config_map['peripherals'].items() if 'network' in y][0]
            orig_protocol_enabled_periph.pop('protocols')
            protocols = protocol_enabled_periph.pop('protocols')
            protocol_enabled_periph['probe2'] = protocols[next(iter(protocols))][0]
        elif additional_info == 3:
            protocol_enabled_periph['probe2'] = "ANALYSIS"


        new_config_path = "/".join(config_path.split('/')[:-1]) + "/.analysis_config.yml"
        save_config(new_config_map, new_config_path)
        return new_config_path
    

    def extract_all_inputs_for_traces(self, output_dir: str) -> list:
        import fuzzware_pipeline.naming_conventions as nc
        import os

        outputs = list()
        # If  we are not in probe mode, we want to look through all files in the output_dir
        current_main = ""
        if "main" in output_dir:
            for part in output_dir.split('/'):
                current_main += f"{part}/"
                if "main" in part:
                    break
        else:
            current_main = "./" # assume we are running from a main 
        files = nc.trace_paths_for_main_dir(current_main, nc.PREFIX_DMA_TRACE)
        filtered_files = []
        for file in files:
            with open(file, "r") as f:
                contents = f.read()

            if "mode: tx" in contents:
                filtered_files.append(file)

        if not filtered_files:
            return []
        files = [nc.input_for_trace_path(x) for x in filtered_files]

        return files


    def extract_outputs(self, output_dir: str) -> list:
        from fuzzware_harness.util import load_config_deep
        import fuzzware_pipeline.naming_conventions as nc
        import os

        outputs = list()
        # If  we are not in probe mode, we want to look through all files in the output_dir
        if not self._probe_mode:
            current_main = ""
            if "main" in output_dir:
                for part in output_dir.split('/'):
                    current_main += f"{part}/"
                    if "main" in part:
                        break
            else:
                current_main = "./" # assume we are running from a main 
            files = nc.trace_paths_for_main_dir(current_main, nc.PREFIX_DMA_TRACE)
        else:
            # If in probe mode the outputs are written to the probe output files
            files = [f'/tmp/{f}' for f in os.listdir('/tmp') if (self._probe_output_file.split('/')[-1] in f)]

        for file in files:
            outputs.append((self.trace_to_queue(file), load_config_deep(file)))
            if self._probe_mode:
                os.remove(file)

        return outputs
    
    def trace_to_queue(self, file: str) -> str:
        """
        Helper to facilitate the input name derivation from a dma trace file
        """
        return  str(file).replace("traces", "queue").replace("dma_", "")

    def get_config_field(self, config_map: dict) -> dict:
        networks = [y['network'] for x,y in config_map['peripherals'].items() if 'network' in y]
        if not networks:
            return None
        return networks[0]

    def write_config(self, config_map: dict, output_file: str):
        from fuzzware_pipeline.util.config import save_config
        save_config(config_map, output_file)

    def overwrite_trace_from_input(self, trace: dict, input_file: str):
        import fuzzware_pipeline.naming_conventions as nc
        from fuzzware_pipeline.util.config import save_config
        dma_trace = nc.trace_paths_for_input(input_file)[-1]
        save_config(trace, dma_trace)


    
    def trim_input(self, input_file: str, config_path: str) -> str:
        # run target to create a dma trace
        from fuzzware_pipeline.run_target import run_target
        from fuzzware_harness.util import load_config_deep
        import os
        import subprocess

        config_map = load_config_deep(config_path) # TODO as argument
        network = [y['network'] for x,y in config_map['peripherals'].items() if 'network' in y][0]
        if not 'protocols' in network or not network['protocols']:
            # initial case
            return input_file

        # second case
        dma_file = f"/tmp/dma_test.yml_{uuid.uuid4()}"
        extra_args = ['--dma-trace-out', dma_file]
        run_target(config_path, input_file, extra_args, silent=True, stdout=subprocess.DEVNULL)
        # use that trace to trim the input
        dma_run = load_config_deep(dma_file)
        # first extract only the rx packts
        rx_pkts = [x for x in dma_run['packets'] if 'mode' in x and x['mode'] == 'rx']
        known_packets = len(network['protocols'])
        total_packets = len(rx_pkts)
        # now we want to only keep | known packet | of input and discard all remaining packet bytes
        print(f"total_packets: {total_packets}")
        print(f"knonw_packets: {known_packets}")
        if total_packets <= known_packets:
            return None
        # now we want to remove all packets after the first {known packets}, from the packet
        with open(input_file, 'rb') as f:
            modified_input = f.read()


        for i in range(total_packets -1, known_packets-1 , -1):
            pkt = rx_pkts[i] # dict
            print(f"[trim_input]: {pkt['start_cursor']}, {pkt['next_cursor']}")
            modified_input = modified_input[:pkt['start_cursor']] + modified_input[pkt['next_cursor']:]

        # store the input and return it        total_packets = dma_run
        self._input_file = f"/tmp/modified_input{uuid.uuid4()}.bin"
        with open(self._input_file, "wb") as f:
            f.write(modified_input)

        os.remove(dma_file)

        return self._input_file 
    
    def best_input_from_outputs(self, outputs: dict, defined_packets: int):
        """
        We want to select the best fuzzing input for analysis by analyzing how often the inserted packets are actually accessed.
        To do so we execute the inputs and use the ram traces to calculate the number of accesses.
        """
        from fuzzware_harness.tracing.serialization import parse_mem_trace
        import os
        choice = ""
        max_nr = 0
        ram_file = f"/tmp/.test_ram_trace.txt_{uuid.uuid4()}"
        bb_file =f"{ram_file}_bb"
        dma_file =f"{ram_file}_dma"

        knowledge = [(file, x['packets']) for file,x in outputs if 'packets' in x]
        for file, entries in knowledge:
            if len([x for x in entries if x['mode'] == 'rx']):
                # first run the input
                config = '/'.join(file.split('/')[:-4]) + "/.np_only_config.yml"

                self.run_target(config, file, ram_file)

                # next parse dma trace
                index = 0
                dma_trace = parse_dma_file(dma_file)
                if not 'packets' in dma_trace:
                    continue
                

                dma_trace = dma_trace['packets']
                dma_trace = [x for x in dma_trace if x['mode'] == 'rx']
                if not dma_trace:
                    continue
                threshold = dma_trace[index]['packet_size']
                cur_addr = dma_trace[index]['buffer']
                cur_val = dma_trace[index]['data'] # bytes!
                cur_event_id = dma_trace[index]['event_id']
                next_event_id = dma_trace[index + 1]['event_id'] if index + 1 in dma_trace else 0xffffffff

                # then  parse the ram trace
                ram_trace = parse_mem_trace(ram_file)
                accesses = 0

                for event_id, pc, lr, mode, size, address, val_text in ram_trace:
                    pre_index = index
                    # if we reached the  next dma insertion look at the next trace entry
                    if  event_id > next_event_id:
                        index += 1
                    elif address >= cur_addr and address < cur_addr + threshold and cur_event_id < event_id:
                        # if a write occurs we stop considering accesses to the associated memory
                        if mode == "w":
                            index += 1
                        if mode == "r":
                            # found an access
                            accesses += 1
                            index += 1
                
                    if index != pre_index:
                        if index >= len(dma_trace):
                            break
                        cur_addr = dma_trace[index]['buffer']
                        cur_val = dma_trace[index]['data'] # bytes!
                        cur_event_id = dma_trace[index]['event_id']
                        next_event_id = dma_trace[index + 1]['event_id'] if index + 1 in dma_trace else 0xffffffff
                        threshold = dma_trace[index]['packet_size']

                if accesses > max_nr:
                    max_nr = accesses
                    choice = file
                print(f"[best inputs]  {file} we found {accesses} accesses for {defined_packets} protocols; cur_addr = {cur_addr:#x}; size = {threshold:#x} ({len(ram_trace)})")
                
                if accesses > defined_packets:
                    print(f"[best inputs] breaking because we found {accesses} accesses for {defined_packets} protocols")
                    break


        if ram_file and os.path.exists(ram_file):
            os.remove(ram_file)
        if bb_file and os.path.exists(bb_file):
            os.remove(bb_file)
        if dma_file and os.path.exists(dma_file):
            os.remove(dma_file)

        return choice
        
def parse_dma_file(path: str) -> dict:
    from fuzzware_harness.util import load_config_deep
    return load_config_deep(path)

