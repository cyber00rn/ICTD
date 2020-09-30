import pcap

from multiprocessing import Process, Queue

class NetworkCapture():
    """ network device name"""
    network_device_name = ""
    """Queue size"""
    QUEUE_SIZE = 20000

    def __init__(self, lpu_queue: Queue, network_dev: str):
        self.lpu = lpu_queue
        self.network_device_name = network_dev

    def capture(self):
        try:

            devs = pcap.findalldevs()
            dev_name = self.network_device_name
            find_flag = False
            for each_dev in devs:
                if each_dev == str(dev_name):
                    find_flag = True
                    break
            if not find_flag:
                return "[Error] There is no such network device"

            pc = pcap.pcap(dev_name, promisc=True, immediate=True, timeout_ms=40)

            for ptime, pdata in pc:
                network_data = {}
                network_data['packet_time'] = ptime
                network_data['raw_data'] = pdata
                """put packet to queue"""
                self.lpu.put(network_data)
        except Exception as e:
            print("Occur error " + str(e))
