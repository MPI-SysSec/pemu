# Dummy plugin api
# Pemu + Hoedur requires an implemented version, but for fuzzware we can just return dummy values, where necessary

class APIGadget:
    def __init__(self):
        return

    def update_fuzzing_input(self, new_fuzz):
        return
    def set_input_id(self, input_id):
        return
    def get_input_id(self): 
        return 0
    def reset_fuzzing_input(self):
        return
    def set_channel(self, channel):
        return
    def consume_channel(self):
        return -1 # i.e., no channel info

    def get_bytes(self, size):
        return []
    def set_packet(self, packet):
        return
    def reset_packet(self):
        return
    def get_packet(self):
        return []
    def set_packet(self, packet):
        return
    def set_inspect_results(self, val):
        return
    def consume_inspect_results(self):
        return True
    def set_random(self):
        return
    def consume_random(self):
        return True
