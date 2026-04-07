from .comm_interface import FuzzwareCommunicator
from .comm_interface import CommunicatorInterface
import time
import logging

FIRST_ANALYSIS = 100
ANALYSIS_SIZE = 50
protocol_specifics = {'TCP': 2, 'DHCP': 2}

PROTOCOL = 0
COUNT = 1
logger = None

NOTHING_FOUND = 0
RES_FOUND = 1
FIRST_TIME_RES_FOUND = 2

NOTHING = 0
RETRY = 1
EXTEND = 2
def prepare_config_for_trimming(network: dict):
    # Essentially we want to check if an protcol specifics are not entered with their value
    # E.g., Only one DHCP message was written to
    if not 'protocols' in network:
        return
    trimmed_protocols = {}
    next_one = ""
    for name, protocols in network['protocols']:
        
        if next_one:
            if next_one[PROTOCOL] in protocols:
                if next_one[COUNT] + 1 == protocol_specifics[next_one[PROTOCOL]]:
                    # everything fine
                    next_one = ""
                else:
                    next_one = (next_one[PROTOCOL], next_one[COUNT] + 1)
                trimmed_protocols[name] = protocols
                continue
            else:
                for i in range(next_one[COUNT] + 1, protocol_specifics[next_one[PROTOCOL]] + 1):

                    pass
                
        trimmed_protocols[name] = protocols
        for p in protocols:
            if p in protocol_specifics:
                next_one = (p, 1)
                break
        pass

    return

def fuzzware_merge_config(config_map: dict, latest_config: dict, communicator):
    """
    During the fuzzware pipeline, config_map contains the default config + all protocol updates.
    Therfore, we also want to extract the network configuration from the latest config and replace the default
    config with it.

    Args:
        config_map:     Dictionary containing the current config
        config_path:       Path to the current main directory's config
    """
    latest_network = communicator.get_config_field(latest_config)
    default_network = communicator.get_config_field(config_map)

    if latest_network and default_network != None:
        if 'apriori' in latest_network:
            default_network['apriori'] = latest_network['apriori']
        if 'protocols' in latest_network:
            default_network['protocols'] = latest_network['protocols']

    return

def active_analysis(input_file: str, config_map: dict, config_path: str, communicator: CommunicatorInterface, additional_info=NOTHING) -> int:
    """ 
    Perform the Active probing analysis
    Args:
        input_file:     Path of the input file
        config_map:     Dictionary containing the current config
        config_path:    Path to the current config
        communicator:   Communicator object
        additional_info: Information on the phase of the analysis
    
    Returns:
        1 if an update was found, else 0
    """
    # first, a baseline run
    network = communicator.get_config_field(config_map)
    protocols = network['protocols'] if 'protocols' in network else None

    np_only_config = communicator.np_only_config(config_map, config_path)

    communicator.run_target(np_only_config, input_file)
    baseline_coverage = set(communicator.parse_trace())
    import os 
    os.remove(np_only_config)

    output_file = "./.output_test.yml"
    probe_config_path = communicator.enable_probe_mode(config_map, config_path, additional_info)

    result = communicator.extract_outputs(input_file)
    # next trim the input, i.e. remove the "random" DMA part
    trimmed_in = communicator.trim_input(input_file, config_path)
    if not trimmed_in:
        logger.debug(f"[active_analysis] not enough packets yet")
        return
    
    # next check if there are new probe inputs found
    communicator.run_target(probe_config_path, trimmed_in)
    next_coverage = communicator.parse_trace()
    result = communicator.extract_outputs(input_file)
    if not result:
        logger.debug("mhhhh")
        return 0
    logger.debug(result)
    result = result[0][1]['probe'] if 'probe' in result[0][1] else None
    if not result:
        return 0
    
    if not 'protocols' in network or not network['protocols']:
        analysis_size = FIRST_ANALYSIS
    else:
        analysis_size = ANALYSIS_SIZE
    # Perform ANALYSIS_SIZE runs
    logger.debug(f"Analysis size is {analysis_size}")
    mapping = dict()
    for i in range(analysis_size):
        communicator.run_target(probe_config_path, trimmed_in) 
        result = communicator.extract_outputs(input_file)[0][1]
        
        coverage = communicator.parse_trace()
        if not 'probe' in result:
            continue
        res_string = '.'.join([x for x in result['probe']])
        if res_string in mapping:
            mapping[res_string] |= set(coverage) # union it
        else:
            mapping[res_string] = set(coverage)

        print(f"{res_string}: {result['transceived_packets']}:{len(set(coverage))}")
    
    # Now, perform analysis
    # we first remove all basic blocks found in the baseline coverage 
    for name, field in mapping.items():
        mapping[name] = field - baseline_coverage

    to_pop = list()

    for name, field in mapping.items():
        for cmp_name, cmp_field in mapping.items():
            if len(field) == len(cmp_field) and field == cmp_field and name != cmp_name:
                if len(name.split('.')) < len(cmp_name.split('.')) and name.split('.')[0] == cmp_name.split('.')[0]:
                    print(f"Adding {cmp_name} to pop list after comparing it with {name}")
                    to_pop.append(cmp_name)
                    continue

    print(to_pop)
    for name in set(to_pop):
        mapping.pop(name)
                

    # next we calcuate all non unique bbs, i.e., bbs covered by more than on set
    any_intersect = set()
    for name, field in mapping.items():
        for other_name, other_field in mapping.items():
            if name == other_name:
                continue
            any_intersect |= (field & other_field)

    # last we remove all non uniqe bbs from the result sets to analyze the truly unique bbs
    unique_bbs = dict()
    for name, field in mapping.items():
        unique_bbs[name] = field - any_intersect

    for name, field in unique_bbs.items():
        logger.debug(f"{name}: {', '.join([hex(x) for x in field])}")

    # modify the config_map to include the best option
    winners_sorted = sorted([(name, len(unique)) for name, unique in unique_bbs.items()], key=lambda x: x[1])
    logger.debug(winners_sorted)
    if winners_sorted[-1][1] == 0:
        # found nothing
        if additional_info == FIRST_TIME_RES_FOUND:
            network['protocols'] = protocols
            return RES_FOUND
        logger.debug(f"[active_analysis] no covering bbs found")
        return NOTHING_FOUND
    winner = sorted([(name, len(unique)) for name, unique in unique_bbs.items()], key=lambda x: x[1])[-1][0].split('.')
    

    # Be aware: Naming your packets p{random}, can lead to them being overwritten here!
    if not 'protocols' in network:
        network['protocols'] = dict()
    for w in winner:
        if w in protocol_specifics:
            for i in range(protocol_specifics[w]):
                network['protocols'][f'p{len(network["protocols"]) + 1}'] = winner
            break
    else:
        network['protocols'][f'p{len(network["protocols"]) + 1}'] = winner

    logger.debug(winner)
    logger.debug(network)
    if winner:
        if analysis_size == FIRST_ANALYSIS:
            return FIRST_TIME_RES_FOUND
        else:
            return RES_FOUND

    return NOTHING_FOUND




def passive_analysis(output_dir: str, config_map: dict, config_path: str, communicator: CommunicatorInterface) -> (int, str or None):
    """ 
    Analyze the output files of the individual emulator runs, created during part of the fuzzing campaign.
    Look for new/unknown values as well as new protocols. Write them directly to the configuration.

    Args:
        output_dir:     Path to the directory, from which the outputs can be sourced
        config_map:     Current config state as a dictionary
        communicator:   Communicator object, which facilitates the communication with the fuzzing platform

    Returns:
        - 1 if new field values or protocols were found, else return 0
        - Path to the most promising input file or None
    """
    choice = None
    changes = 0
    vote_dict = dict()
    result_dict = dict()
    protocol_dict = dict()
    used_protocols = list()

    communicator.disable_probe_mode()
    logger.debug(f"[passive_analysis] entering and extracting outputs from trace")
    # extract outputs
    extracted_results = communicator.extract_outputs(output_dir)
    if not extracted_results:
        return 0, choice
    network = communicator.get_config_field(config_map)
    defined_protocols = len(network['protocols']) if 'protocols' in network and network['protocols'] else 0

    if not 'protocols' in network or not network['protocols']:
        logger.debug(f"[passive_analysis] no known protocols yet; searching for most optimal input")
        np_only_config =  communicator.np_only_config(config_map, config_path)
        if np_only_config:
            choice = communicator.best_input_from_outputs(extracted_results, defined_protocols)
            import os 
            os.remove(np_only_config)
        return 0, choice
    
    # As there may be more data in the results, first extract only the network related information
    protocol_results = [x['new_protocols'] for file,x in extracted_results if 'new_protocols' in x]
    results = [x['network'] for file,x in extracted_results if 'network' in x]

    # Unify the collected information to a single dictionary containing all votes
    for output in results:
        for field, field_results in output.items():
            if field not in vote_dict:
                vote_dict[field] = dict()
            for val, vote in field_results.items():
                if val in vote_dict[field]:
                    vote_dict[field][val] += vote
                else:
                    vote_dict[field][val] = vote

    # Next, extract the highest votes for every header field
    for header_field, votes in vote_dict.items():
        max_vote = (0, 0) # vote, val
        for val, vote in votes.items():
            if vote > max_vote[0]:
                max_vote = (vote, val)

        if max_vote[0] > 0:
            result_dict[header_field] = max_vote[1]

    # Now check if we can add any of the results to our knowledge base
    if result_dict:
        if 'apriori' in network:
            for header_field, val in result_dict.items():
                if not header_field in network['apriori']:
                    changes = 1
                    network['apriori'][header_field] = val
                else:
                    if network['apriori'][header_field] == val:
                        continue 
                    total_votes = 0
                    max_votes = 0
                    for new_val, vote in vote_dict[header_field].items():
                        if vote > max_votes:
                            max_votes = vote
                        total_votes += vote
                    if max_votes > 0.9 * total_votes:
                        # replace
                        logger.debug("CHANGING EXISITNG DATA")
                        changes = 1
                        network['apriori'][header_field] = val    
        else:
            changes = 1
            network['apriori'] = dict()
            for header_field, val in result_dict.items():
                network['apriori'][header_field] = val


    # Check whether we can add any new protocols
    for protocol_result in protocol_results:
        for cursor, protocols in protocol_result.items():
            if not cursor in protocol_dict:
                protocol_dict[cursor] = list()
            protocol_dict[cursor].append(protocols)
    used_protocols = network['protocols'] if 'protocols' in network else None
    if not used_protocols:
        import sys
        logger.debug("(!) How could this happen to me???"); sys.exit()

    if protocol_dict and 'static' not in network: 
        # only one entry per cursor
        changes = 1
        
        for cursor, protocol_list in protocol_dict.items():
            
            if len(protocol_list) == 1:
                protocol_dict[cursor] = protocol_list[0]
                continue
            # for now choose the most extensive one 
            max_index_and_len = (0,0)
            for i in  range(len(protocol_list)):
                if len(protocol_list[i]) > max_index_and_len[1]:
                    max_index_and_len = (i, len(protocol_list[i]))
            
            protocol_dict[cursor] = protocol_list[max_index_and_len[0]]
        
        # we want every protocol only once, with the lowest cursor
        already_checked = dict()

        for cursor, protocol_list in protocol_dict.items():
            if '.'.join(protocol_list) not in already_checked: 
                already_checked['.'.join(protocol_list)] = list()
            already_checked['.'.join(protocol_list)].append(cursor)

        for prot, cursors in already_checked.items():
            for cursor in sorted(cursors)[1:]:
                protocol_dict.pop(cursor)
        
        # slot the changes to the old protocol order
        slots = [network['protocols'][x] for x in network['protocols']]
        if len(slots) < max(protocol_dict.keys()):
            slots = slots + [slots[-1]] * (max(protocol_dict.keys()) - len(slots))
        for cursor in range(max(protocol_dict.keys()), -1, -1):
            protocol_specific_multiplier = 1
            if cursor not in protocol_dict:
                continue
            if protocol_dict[cursor][-1] in protocol_specifics:
                protocol_specific_multiplier = protocol_specifics[protocol_dict[cursor][-1]]

            slots = slots[:cursor] + ([protocol_dict[cursor]] * protocol_specific_multiplier)+ slots[cursor:]

        # write back the slots
        for i in range(len(slots)):
            network['protocols'][f'p{i}'] = slots[i]

    logger.debug(f"[passive_analysis] results of the passive analysis are: {changes}")
    print(network)
    if not changes and 'static' not in network:
        logger.debug(f"[passive_analysis] no new results; searching for most optimal input for further analysis")
        np_only_config =  communicator.np_only_config(config_map, config_path)
        if np_only_config:
            choice = communicator.best_input_from_outputs(extracted_results, defined_protocols)
            import os 
            os.remove(np_only_config)

    return changes, choice



def rerun_dma(main_dir: str, config_path: str, config: dict, communicator: CommunicatorInterface) -> bool:
    """
    Rerun all inputs that lead to dma traces
    
    """
    inputs = communicator.extract_all_inputs_for_traces(main_dir)
    tmp_config = '/'.join(config_path.split('/')[:-1]) + '/.rerun_config'
    tmp_config = communicator.enable_probe_mode(config, config_path, 3)
    found_smth = False


    for inp in inputs:
        communicator.run_target(tmp_config, inp) 
        result = communicator.extract_outputs(inp)[0][1]
        if 'new_protocols' not in result and 'new_val' not in result:
            continue
        found_smth = True
        network = result['network']
        communicator.overwrite_trace_from_input(result, inp)



    return found_smth


def debug(main_dir: str, config_map: dict, config_path: str, queue_in=None, parsed_logger=None) -> int:
    global logger
    if not parsed_logger:
        logging.basicConfig(level=logging.DEBUG, format='%(message)s')
        logger = logging.getLogger("analysis-logger")
    else:
        logger = parsed_logger
    logger.debug(f"[fuzzware_probe_analysis] entering...")
    if main_dir == "main000":
        return 0
    if not 'peripherals' in config_map:
        return 0
    
    from fuzzware_harness.util import load_config_deep 
    analysis_config = load_config_deep(config_path)
    logger.debug(f"[fuzzware_probe_analysis] setting up the communicator and merging configurations")
    communicator = FuzzwareCommunicator(analysis_config, config_path)
    if communicator.get_config_field(analysis_config) == None:
        return 0
    if communicator.get_config_field(analysis_config) == dict():
        first_analysis = True
    pre_merge = time.time()
    rerun_dma(main_dir, config_path, analysis_config, communicator)


def fuzzware_probe_analysis(main_dir: str, config_map: dict, config_path: str, queue_in=None, parsed_logger=None) -> int:
    """
    Perform the runtime analysis of a firmware running with fuzzware, and add changes to the config.
    
    Args:
        main_dir:       Path to the current main directory of fuzzing campaign
        config_map:     Current configuration file as a dictionary
        config_path:    The path of the configuration file used during the last main session
        queue_in:       Supply a specific input that shall be used to actively detect new protocols
    """
    # sanity check, but this should (in theory) never happen
    first_analysis = False
    global logger
    if not parsed_logger:
        logging.basicConfig(level=logging.DEBUG, format='%(message)s')
        logger = logging.getLogger("analysis-logger")
    else:
        logger = parsed_logger
    logger.debug(f"[fuzzware_probe_analysis] entering...")
    if main_dir == "main000":
        return 0
    if not 'peripherals' in config_map:
        return 0
    
    from fuzzware_harness.util import load_config_deep 
    analysis_config = load_config_deep(config_path)
    logger.debug(f"[fuzzware_probe_analysis] setting up the communicator and merging configurations")
    communicator = FuzzwareCommunicator(analysis_config, config_path)
    if communicator.get_config_field(analysis_config) == None:
        return 0
    if communicator.get_config_field(analysis_config) == dict():
        first_analysis = True
    pre_merge = time.time()
    if 'analysis' in communicator.get_config_field(analysis_config) and communicator.get_config_field(analysis_config)['analysis'] == False:
        return 0

    # PASSIVE 
    logger.debug(f"[fuzzware_probe_analysis] Performing passive analysis")
    pre_passive = time.time()
    logger.debug(f"[fuzzware_probe_analysis] Merging took {pre_passive-pre_merge}s")
    if queue_in:
        found_change, _ = passive_analysis(main_dir, analysis_config, config_path, communicator)
    else:
        found_change, queue_in = passive_analysis(main_dir, analysis_config, config_path, communicator)

    
    pre_active = time.time()
    logger.debug(f"[fuzzware_probe_analysis] Passive analysis took {pre_active - pre_passive}s")
    logger.debug(f"[fuzzware_probe_analysis] found_change is {found_change}")
    if (found_change or not queue_in) or 'static' in communicator.get_config_field(analysis_config):
        fuzzware_merge_config(config_map, analysis_config, communicator)
        return found_change
        
    # ACTIVE
    logger.debug(f"[fuzzware_probe_analysis] performing active analysis with the input {queue_in}")
    ret_val = active_analysis(queue_in, analysis_config, config_path, communicator)
    finish_time = time.time()
    logger.debug(f"[fuzzware_probe_analysis] Merging took {finish_time - pre_passive}s")
    if ret_val == NOTHING_FOUND and not communicator.get_config_field(analysis_config):
        ret_val = active_analysis(queue_in, analysis_config, config_path, communicator, additional_info=RETRY)
    logger.debug(f"[fuzzware_probe_analysis] ret_val is {ret_val}")

    if ret_val == FIRST_TIME_RES_FOUND:
        ret_val = active_analysis(queue_in, analysis_config, config_path, communicator, additional_info=EXTEND)

    
    if first_analysis and ret_val != NOTHING_FOUND:
        print(analysis_config)
        if rerun_dma(main_dir, config_path, analysis_config, communicator):
            found_change, _ = passive_analysis(main_dir, analysis_config, config_path, communicator)
        print(analysis_config)


    fuzzware_merge_config(config_map, analysis_config, communicator)
    print(communicator.get_config_field(config_map))
    return ret_val

def hoedur_analysis(main_dir: str, config_map: dict, config_path: str, queue_in=None, parsed_logger=None) -> int:
    return 1
def hoedur_passive_analysis(main_dir: str, config_map: dict, config_path: str, queue_in=None, parsed_logger=None) -> int:
    return 1

def main():
    """
    For debugging
    """
    import sys
    from fuzzware_harness.util import load_config_deep
    queue_in = sys.argv[2]
    config_path = sys.argv[1]
    config_map = load_config_deep(config_path)


"""
For the sake of the modularity of this analysis we need to make the following assumptions:
1.)
    There is some form of configuration file, that is used to start the emulator/fuzzer.
    Within this config file, the artificial network controller is configured as well.

2.)
    The config file is stored in a certain path, which we know (i.e., we get parsed)

3.) (Optional)
    We have access to the an input, or rather its path. That we can use to probe.
    However, if that is not the case, we can fall back to the output analysis by looking at
    the files created by the packet parser.

With these preconditions it is necessary to add that, the detection/analysis does not know how
the config formats and emulation runs work. It is the engineers job to provide the suitable functions
in the comm_interface
"""

if __name__ == "__main__": main()
