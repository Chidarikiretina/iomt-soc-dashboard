"""
Minimal helpers imported from IoMT_Anomaly_Detection_Project
so the backend doesn't need the full project on sys.path.
"""
import pandas as pd


LABEL_SUFFIX_PATTERNS = [
    "-WiFi", "-MQTT", "_WiFi", "_MQTT",
    " WiFi", " MQTT", "-Attacks", "_Attacks",
]

LABEL_CATEGORY_MAP = {
    # Benign
    "BenignTraffic": "Benign",
    "Benign":        "Benign",
    # DDoS
    "DDoS-RSTFINFlood":        "DDoS",
    "DDoS-PSHACK_Flood":       "DDoS",
    "DDoS-SYN_Flood":          "DDoS",
    "DDoS-UDP_Flood":          "DDoS",
    "DDoS-TCP_Flood":          "DDoS",
    "DDoS-ICMP_Flood":         "DDoS",
    "DDoS-HTTP_Flood":         "DDoS",
    "DDoS-SlowLoris":          "DDoS",
    "DDoS-ICMP_Fragmentation": "DDoS",
    "DDoS-ACK_Fragmentation":  "DDoS",
    "DDoS-UDP_Fragmentation":  "DDoS",
    # DoS
    "DoS-UDP_Flood":   "DoS",
    "DoS-SYN_Flood":   "DoS",
    "DoS-TCP_Flood":   "DoS",
    "DoS-HTTP_Flood":  "DoS",
    # Recon
    "Recon-HostDiscovery": "Recon",
    "Recon-OSScan":        "Recon",
    "Recon-PortScan":      "Recon",
    "Recon-PingSweep":     "Recon",
    "Recon-VulScan":       "Recon",
    # MQTT
    "MQTT-Publish":    "MQTT",
    "MQTT-Subscribe":  "MQTT",
    "MQTT-Connect":    "MQTT",
    # Spoofing
    "DNS_Spoofing":      "Spoofing",
    "MITM-ArpSpoofing":  "Spoofing",
    "ARP_Spoofing":      "Spoofing",
}


def strip_label_suffixes(series: pd.Series) -> pd.Series:
    result = series.copy()
    for suffix in LABEL_SUFFIX_PATTERNS:
        result = result.str.replace(suffix, "", regex=False)
    return result.str.strip()


def map_labels_to_categories(series: pd.Series) -> pd.Series:
    def map_one(label):
        if label in LABEL_CATEGORY_MAP:
            return LABEL_CATEGORY_MAP[label]
        # CICIoMT2024-style labels: TCP_IP-DDoS-UDP2_train, Benign_train, etc.
        clean = label.replace('_train', '').replace('_test', '').strip()
        lc = clean.lower()
        if lc == 'benign' or lc.startswith('benign'):
            return 'Benign'
        if 'ddos' in lc:
            return 'DDoS'
        if 'dos' in lc:
            return 'DoS'
        if 'recon' in lc or 'scan' in lc or 'sweep' in lc:
            return 'Recon'
        if 'spoof' in lc or 'arp' in lc or 'mitm' in lc:
            return 'Spoofing'
        if 'mqtt' in lc:
            return 'MQTT'
        return 'Unknown'
    return series.map(map_one)


class DataLoader:
    pass
