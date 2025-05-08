import os
import subprocess
import time
import re
from pprint import pprint
from collections import Counter

def get_physical_interfaces():
    base_path = "/sys/class/net"
    interfaces = []

    for iface in os.listdir(base_path):
        device_path = os.path.join(base_path, iface, "device")
        if os.path.isdir(device_path):
            interfaces.append(iface)
    return interfaces


def get_speed(interface):
    with open(f"/sys/class/net/{interface}/speed", "r") as fd:
        speed = fd.read().strip()
    fd.close()
    return speed


def get_ethtool_stats(interface):
    try:
        result = subprocess.run(
            ["ethtool", "-S", interface],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=True
        )
        return result.stdout
    except subprocess.CalledProcessError as e:
        return None


def parse_ethtool_stats(raw_output):
    stats = { 'rx_queues': [], 'tx_queues': [] }
    values = {}
    for line in raw_output.splitlines():
        if ':' in line:
            if 'statistic' not in line:
                key, value = line.strip().split(':', 1)
                if 'Rx Queue' in key:
                    if len(values):
                        queue.append(values)
                        values = {}
                    queue = stats['rx_queues']
                    values['queue'] = value.strip()
                elif 'Tx Queue' in key:
                    if len(values):
                        queue.append(values)
                        values = {}
                    queue = stats['tx_queues']
                    values['queue'] = value.strip()
                else:
                    values[key.strip()] = value.strip()
    if len(values):
        queue.append(values)
    return stats


def diff_queues(snapshot1, snapshot2, key='queue'):
    def parse_int(val):
        try:
            return int(val)
        except (ValueError, TypeError):
            return 0

    # index por número da queue
    index1 = {q[key]: q for q in snapshot1}
    index2 = {q[key]: q for q in snapshot2}
    diff_result = []

    for q_id in index1:
        if q_id in index2:
            q1 = index1[q_id]
            q2 = index2[q_id]
            diff_entry = {key: q_id}
            for field in q1:
                if field == key:
                    continue
                v1 = parse_int(q1.get(field, 0))
                v2 = parse_int(q2.get(field, 0))
                diff_entry[field] = v2 - v1
            diff_result.append(diff_entry)
    return diff_result


'''
sockets: used   Número total de sockets em uso no sistema
TCP: inuse      Sockets TCP atualmente abertos (exclui TIME_WAIT e órfãos)
TCP: orphan     Sockets TCP sem processo associado (usualmente conexões abandonadas)
TCP: tw Conexões em estado TIME_WAIT (aguardando término completo)
TCP: alloc      Sockets TCP alocados (inuse + TIME_WAIT + outras pendentes)
TCP: mem        Memória usada por TCP em páginas (cada página normalmente = 4 KB)
UDP: inuse      Sockets UDP ativos
UDP: mem        Memória usada por UDP (em páginas)
UDPLITE: inuse  Sockets UDPLite ativos (pouco comum)
RAW: inuse      Sockets RAW (usado por ping, traceroute, etc)
'''
def parse_sockstat():
    result = {}
    with open("/proc/net/sockstat", "r") as f:
        for line in f:
            parts = line.split()
            key = parts[0].rstrip(':')
            metrics = dict(zip(parts[1::2], map(int, parts[2::2])))
            result[key] = metrics
    return result


'''
Para obter contagem de conexões TCP por estado
'''
TCP_STATES = {
    '01': 'ESTABLISHED',
    '02': 'SYN_SENT',
    '03': 'SYN_RECV',
    '04': 'FIN_WAIT1',
    '05': 'FIN_WAIT2',
    '06': 'TIME_WAIT',
    '07': 'CLOSE',
    '08': 'CLOSE_WAIT',
    '09': 'LAST_ACK',
    '0A': 'LISTEN',
    '0B': 'CLOSING',
}

def count_tcp_states(path="/proc/net/tcp"):
    state_counter = Counter()
    with open(path, "r") as f:
        next(f)  # skip header
        for line in f:
            fields = line.strip().split()
            state_hex = fields[3]
            state = TCP_STATES.get(state_hex.upper(), 'UNKNOWN')
            state_counter[state] += 1
    return state_counter


'''
fds per process
'''
def collect_open_fds():
    processes = []

    for pid in filter(str.isdigit, os.listdir("/proc")):
        fd_path = f"/proc/{pid}/fd"
        comm_path = f"/proc/{pid}/comm"

        try:
            fd_count = len(os.listdir(fd_path))
            with open(comm_path) as f:
                cmd = f.read().strip()
            processes.append({
                "pid": int(pid),
                "open_fds": fd_count,
                "command": cmd
            })
        except (PermissionError, FileNotFoundError):
            continue  # Processo finalizado ou sem permissão

    return {"processes": processes}

'''
numa statistics
'''
def parse_numastat():
    result = subprocess.run(["numastat"], capture_output=True, text=True)
    lines = result.stdout.strip().splitlines()

    headers = lines[0].split()
    data = {}

    for line in lines[1:]:
        parts = line.split()
        metric = parts[0]
        values = list(map(int, parts[1:]))
        data[metric] = dict(zip(headers, values))

    return data


'''
PF e VF
'''
def read_int(path):
    try:
        return int(open(path).read())
    except:
        return None

def get_pf_vf_counts(pf_iface):
    base = f"/sys/class/net/{pf_iface}/device"
    return {
        "pf": pf_iface,
        "sriov_numvfs": read_int(os.path.join(base, "sriov_numvfs")),
        "sriov_totalvfs": read_int(os.path.join(base, "sriov_totalvfs"))
    }

def get_vf_config(pf_iface):
    output = subprocess.check_output(["ip", "link", "show", pf_iface], text=True)
    vf_data = []
    for line in output.splitlines():
        if "vf" in line:
            match = re.search(r"vf (\d+) MAC ([0-9a-f:]+), VLAN (\d+)", line)
            if match:
                vf_data.append({
                    "vf_index": int(match.group(1)),
                    "mac": match.group(2),
                    "vlan": int(match.group(3))
                })
    return vf_data

def get_vf_stats():
    stats = []
    for iface in os.listdir("/sys/class/net"):
        stat_dir = os.path.join("/sys/class/net", iface, "statistics")
        if os.path.isdir(stat_dir):
            try:
                rx = read_int(os.path.join(stat_dir, "rx_bytes"))
                tx = read_int(os.path.join(stat_dir, "tx_bytes"))
                rx_err = read_int(os.path.join(stat_dir, "rx_errors"))
                tx_drop = read_int(os.path.join(stat_dir, "tx_dropped"))
                stats.append({
                    "interface": iface,
                    "rx_bytes": rx,
                    "tx_bytes": tx,
                    "rx_errors": rx_err,
                    "tx_dropped": tx_drop
                })
            except:
                continue
    return stats

def get_pf_ethtool_stats(pf_iface):
    try:
        output = subprocess.check_output(["ethtool", "-S", pf_iface], text=True)
    except subprocess.CalledProcessError:
        return {}

    stats = {}
    for line in output.splitlines():
        if ":" in line:
            key, val = line.strip().split(":", 1)
            try:
                stats[key.strip()] = int(val.strip())
            except:
                continue
    return stats

def collect_sriov_info(pf_iface):
    return {
        "vf_config": get_vf_config(pf_iface),
        "vf_stats": get_vf_stats(),
        "pf_vf_count": get_pf_vf_counts(pf_iface),
        "pf_ethtool_stats": get_pf_ethtool_stats(pf_iface)
    }




'''
Power draw per CPU core (W)     intel_rapl (calculado ou exporter)
CPU frequency per core (Hz)     node_cpu_scaling_frequency_hertz
Governor mode per core  node_cpu_scaling_governor
Total system power (W)  ipmi_sensor_value ou ipmi_power_watts
'''
def read_file(path):
    try:
        with open(path) as f:
            return f.read().strip()
    except:
        return None

def get_cpu_scaling_info():
    cpu_info = {}
    cpu_path = "/sys/devices/system/cpu/"
    for cpu in sorted([d for d in os.listdir(cpu_path) if d.startswith("cpu") and d[3:].isdigit()]):
        idx = cpu[3:]
        base = os.path.join(cpu_path, cpu, "cpufreq")
        cur = read_file(os.path.join(base, "scaling_cur_freq"))
        minf = read_file(os.path.join(base, "scaling_min_freq"))
        maxf = read_file(os.path.join(base, "scaling_max_freq"))
        gov = read_file(os.path.join(base, "scaling_governor"))
        cpu_info[idx] = {
            "cur_freq_khz": int(cur) if cur else 0,
            "min_freq_khz": int(minf) if minf else 0,
            "max_freq_khz": int(maxf) if maxf else 0,
            "governor": gov if gov else "unknown"
        }
    return cpu_info

def get_rapl_power():
    base_path = "/sys/class/powercap/intel-rapl:0/"
    energy_path = os.path.join(base_path, "energy_uj")
    time_interval = 1  # seconds

    e1 = read_file(energy_path)
    time.sleep(time_interval)
    e2 = read_file(energy_path)

    if e1 is None or e2 is None:
        return None

    e1 = int(e1)
    e2 = int(e2)
    delta_joules = (e2 - e1) / 1_000_000.0  # convert µJ to J
    power_watts = delta_joules / time_interval
    return round(power_watts, 2)

def get_ipmi_power():
    try:
        output = subprocess.check_output(["ipmitool", "sensor"], text=True)
        for line in output.splitlines():
            if "Power" in line and "Watt" in line:
                parts = line.split('|')
                if len(parts) >= 2:
                    label = parts[0].strip()
                    value = parts[1].strip().split()[0]
                    return float(value)
    except Exception as e:
        return None

def get_metrics():
    print("### CPU Frequency & Governor per core")
    cpu_data = get_cpu_scaling_info()
    for core, info in cpu_data.items():
        print(f"cpu{core}_cur_freq_khz: {info['cur_freq_khz']}")
        print(f"cpu{core}_min_freq_khz: {info['min_freq_khz']}")
        print(f"cpu{core}_max_freq_khz: {info['max_freq_khz']}")
        print(f"cpu{core}_governor: {info['governor']}")

    print("\n### CPU Power (RAPL)")
    rapl_power = get_rapl_power()
    if rapl_power is not None:
        print(f"rapl_cpu_power_watts: {rapl_power}")
    else:
        print("rapl_cpu_power_watts: unavailable")

    print("\n### System Power (IPMI)")
    ipmi_power = get_ipmi_power()
    if ipmi_power is not None:
        print(f"ipmi_system_power_watts: {ipmi_power}")
    else:
        print("ipmi_system_power_watts: unavailable")



if __name__ == "__main__":
    physical_ifaces = get_physical_interfaces()
    for iface in physical_ifaces:
        link_speed = get_speed(iface)
        t1 =  int(time.time())
        stats = parse_ethtool_stats(get_ethtool_stats(iface))
        pprint(stats)
        sriov = collect_sriov_info(iface)
        pprint(sriov)
    result = parse_sockstat()
    pprint({'sockstat': result})
    states_v4 = count_tcp_states("/proc/net/tcp")
    pprint({'states_v4': states_v4})
    states_v6 = count_tcp_states("/proc/net/tcp6")
    pprint({'states_v6': states_v6})
    numa_data = parse_numastat()
    pprint({'numa_data': numa_data})
    processes = collect_open_fds()
    pprint({'processes': processes})
    get_metrics()

