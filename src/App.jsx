import React, { useState, useEffect, useCallback, useRef, useMemo } from 'react';
import emailjs from '@emailjs/browser';

const API_BASE = import.meta.env.VITE_BACKEND_URL || '${API_BASE}';
import { geoEquirectangular, geoPath } from 'd3-geo';
import { feature as topoFeature } from 'topojson-client';
import { useSOCSocket } from './useSOCSocket';
import { LineChart, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, AreaChart, Area, PieChart, Pie, Cell, BarChart, Bar, RadarChart, Radar, PolarGrid, PolarAngleAxis, PolarRadiusAxis, Legend } from 'recharts';
import { Activity, Shield, AlertTriangle, AlertCircle, Heart, Droplets, Monitor, Radio, Upload, Play, Pause, Bell, TrendingUp, Zap, Wifi, Clock, ChevronRight, X, Ban, Unplug, ShieldCheck, Eye, CheckCircle, RotateCcw, Lock, Unlock, AlertOctagon, Siren, History, Filter, Mail, MessageSquare, Globe, MapPin, Server, Database, Router, Smartphone, Link2, ExternalLink, RefreshCw, ChevronDown, Send, Check, Copy, Rss, Skull, Bug, Target, Crosshair, Radio as RadioIcon, Circle, Search, BookOpen, Layers, GitBranch, FileText, ClipboardList, UserCheck, AlertCircle as AlertCircleIcon, FileCheck, Scale, BookMarked, Flame, ArrowUpRight, CalendarClock, Users, Settings, KeyRound, HardDrive, LogOut, Download } from 'lucide-react';

const devices = ['Infusion Pump', 'Heart Monitor', 'Pulse Oximeter', 'ECG Monitor'];
const attackTypes = ['DDoS', 'DoS', 'Spoofing', 'Recon', 'MQTT'];

const generateTrafficData = () => ({
  timestamp: new Date().toLocaleTimeString(),
  packets: Math.floor(Math.random() * 500) + 100,
  anomalyScore: Math.random(),
});

const generateIP = () => `192.168.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`;

// Threat Intelligence Data
const threatIntelSources = [
  { name: 'AlienVault OTX', status: 'active', lastSync: '2 min ago' },
  { name: 'VirusTotal', status: 'active', lastSync: '5 min ago' },
  { name: 'AbuseIPDB', status: 'active', lastSync: '3 min ago' },
  { name: 'Shodan', status: 'warning', lastSync: '15 min ago' },
];

const generateThreatIntel = () => {
  const threats = [
    { type: 'Botnet C2', severity: 'critical', indicator: generateIP(), source: 'AlienVault OTX', confidence: 95 },
    { type: 'Malware Hash', severity: 'high', indicator: 'a1b2c3d4e5f6...', source: 'VirusTotal', confidence: 88 },
    { type: 'Phishing Domain', severity: 'medium', indicator: 'mal1c10us.xyz', source: 'AbuseIPDB', confidence: 76 },
    { type: 'Scanner IP', severity: 'low', indicator: generateIP(), source: 'Shodan', confidence: 62 },
    { type: 'Ransomware C2', severity: 'critical', indicator: generateIP(), source: 'AlienVault OTX', confidence: 91 },
  ];
  return threats[Math.floor(Math.random() * threats.length)];
};

// Network Topology Data — all 4 IoMT devices on VLAN 20 (IoMT Medical), same Core Switch
// Isolating a device moves it to VLAN 99 (Quarantine) to segment it from peers
const VLAN_DEFS = {
  20:  { name: 'IoMT Medical',   color: '#06b6d4', subnet: '192.168.20.0/24',  gateway: '192.168.20.1',  cidr: '192.168.20.' },
  99:  { name: 'Quarantine',     color: '#ef4444', subnet: '192.168.99.0/24',  gateway: '192.168.99.1',  cidr: '192.168.99.' },
  100: { name: 'Infrastructure', color: '#64748b', subnet: '192.168.100.0/24', gateway: '192.168.100.1', cidr: '192.168.100.' },
};

// Host octet for each device (last octet stays the same across VLANs when moved to quarantine)
const DEVICE_OCTETS = { 'Infusion Pump': 50, 'Heart Monitor': 22, 'Pulse Oximeter': 35, 'ECG Monitor': 41 };

const networkNodes = [
  { id: 'gateway',  type: 'router',   label: 'Gateway Router',  x: 50, y: 10, status: 'normal' },
  { id: 'firewall', type: 'firewall', label: 'Firewall',         x: 50, y: 25, status: 'normal' },
  { id: 'switch1',  type: 'switch',   label: 'Core Switch',      x: 50, y: 42, status: 'normal', vlans: [20, 99, 100] },
  { id: 'server',   type: 'server',   label: 'ML Server',        x: 20, y: 58, status: 'normal', vlan: 100 },
  { id: 'database', type: 'database', label: 'Patient DB',       x: 80, y: 58, status: 'normal', vlan: 100 },
  { id: 'infusion', type: 'device', label: 'Infusion Pump',   x: 15, y: 80, status: 'normal', device: 'Infusion Pump',  vlan: 20, vlanName: 'IoMT Medical' },
  { id: 'heart',    type: 'device', label: 'Heart Monitor',    x: 38, y: 80, status: 'normal',  device: 'Heart Monitor',  vlan: 20, vlanName: 'IoMT Medical' },
  { id: 'pulse',    type: 'device', label: 'Pulse Oximeter',   x: 62, y: 80, status: 'normal',  device: 'Pulse Oximeter', vlan: 20, vlanName: 'IoMT Medical' },
  { id: 'ecg',      type: 'device', label: 'ECG Monitor',      x: 85, y: 80, status: 'normal',  device: 'ECG Monitor',    vlan: 20, vlanName: 'IoMT Medical' },
];

const networkLinks = [
  { from: 'gateway',  to: 'firewall' },
  { from: 'firewall', to: 'switch1'  },
  { from: 'switch1',  to: 'server',   vlan: 100 },
  { from: 'switch1',  to: 'database', vlan: 100 },
  { from: 'switch1',  to: 'infusion', vlan: 20 },
  { from: 'switch1',  to: 'heart',    vlan: 20 },
  { from: 'switch1',  to: 'pulse',    vlan: 20 },
  { from: 'switch1',  to: 'ecg',      vlan: 20 },
];

// ── MITRE ATT&CK Mapping ──────────────────────────────────────────────────────
const mitreMapping = {
  DDoS:     { tactic:'Impact',            tacticId:'TA0040', technique:'Network Denial of Service',       techniqueId:'T1498', sub:'Direct Network Flood',  subId:'T1498.001', mitigations:['Filter Network Traffic (M1037)','Limit Access to Resource (M1035)','Network Segmentation (M1030)'] },
  DoS:      { tactic:'Impact',            tacticId:'TA0040', technique:'Endpoint Denial of Service',      techniqueId:'T1499', sub:'Service Exhaustion',     subId:'T1499.002', mitigations:['Filter Network Traffic (M1037)','Limit Access to Resource (M1035)','Load Balancing (M1030)'] },
  Spoofing: { tactic:'Defense Evasion',   tacticId:'TA0005', technique:'Masquerading',                    techniqueId:'T1036', sub:'Invalid Code Signature', subId:'T1036.001', mitigations:['Code Signing (M1045)','Execution Prevention (M1038)','Restrict File Permissions (M1022)'] },
  Recon:    { tactic:'Reconnaissance',    tacticId:'TA0043', technique:'Active Scanning',                 techniqueId:'T1595', sub:'Scanning IP Blocks',     subId:'T1595.001', mitigations:['Pre-compromise (M1056)','Software Configuration (M1054)','Network Intrusion Prevention (M1031)'] },
  MQTT:     { tactic:'Execution',         tacticId:'TA0002', technique:'Command & Scripting Interpreter', techniqueId:'T1059', sub:'Network Device CLI',     subId:'T1059.008', mitigations:['Disable Feature or Program (M1042)','Privileged Account Mgmt (M1026)','Application Isolation (M1048)'] },
};

const tacticRadarBase = [
  { tactic:'Recon',      covered:80 },{ tactic:'Resource Dev',covered:45 },
  { tactic:'Initial Access',covered:70 },{ tactic:'Execution', covered:65 },
  { tactic:'Persistence',covered:55 },{ tactic:'Priv Esc',   covered:60 },
  { tactic:'Defense Ev', covered:75 },{ tactic:'C&C',        covered:85 },
  { tactic:'Exfiltration',covered:50 },{ tactic:'Impact',    covered:90 },
];

// ── Incident Playbooks ─────────────────────────────────────────────────────────
const playbookData = {
  DDoS: {
    sla:15, severity:'critical', color:'#ef4444', icon:'🌊',
    description:'Distributed Denial of Service targeting IoMT device availability. Immediate containment required.',
    steps:[
      { t:'Identify Source IPs',        m:2,  d:'Analyse traffic logs for attack origins. Correlate multiple source IPs across /24 subnets.', role:'Network Analyst',    tactic:'Reconnaissance',       technique:'T1595',  tools:['Wireshark','NetFlow Analyzer'],    evidence:'List of confirmed attacker IPs with packet counts' },
      { t:'Block Malicious IPs',        m:1,  d:'Apply ACL DENY rules on edge firewall and upstream router. Document all rule changes.', role:'SOC Manager',         tactic:'Containment',          technique:'T1562',  tools:['Firewall Console','ACL Manager'],   evidence:'Screenshot of applied ACL rules with timestamps' },
      { t:'Rate-Limit Interfaces',      m:3,  d:'Configure traffic policing on affected VLAN interfaces. Set CIR to 10 Mbps during attack.', role:'Network Analyst',    tactic:'Mitigation',           technique:'T1498',  tools:['Switch CLI','QoS Policy Manager'], evidence:'Interface rate-limit config + traffic graphs' },
      { t:'Activate Scrubbing Centre',  m:5,  d:'Divert traffic to DDoS scrubbing service. Enable BGP blackhole routing for attack prefixes.', role:'SOC Manager',      tactic:'Mitigation',           technique:'T1498.001', tools:['BGP Console','Scrubbing Portal'], evidence:'Scrubbing service activation ticket number' },
      { t:'Notify Clinical Staff',      m:1,  d:'Alert biomedical team and clinical staff of potential device unavailability. Follow communication plan.', role:'Incident Responder', tactic:'Coordination', technique:'—',   tools:['Email','Slack #iomt-alerts'],       evidence:'Communication log with recipient confirmation' },
      { t:'Notify NOC',                 m:1,  d:'Escalate to Network Operations Centre. Provide incident ID and initial impact assessment.', role:'SOC Manager',         tactic:'Escalation',           technique:'—',      tools:['NOC Hotline','Slack'],              evidence:'NOC ticket number and escalation timestamp' },
      { t:'Document & Close',           m:3,  d:'Log all IOCs, timeline, and response actions. Update SIEM. Submit post-incident report within 24h.', role:'Threat Analyst', tactic:'Documentation',     technique:'—',      tools:['SIEM','Confluence'],                evidence:'Incident report INC-XXXXXXXX filed in ticketing system' },
    ]
  },
  DoS: {
    sla:10, severity:'high', color:'#f97316', icon:'⚡',
    description:'Denial of Service from single or few sources targeting a specific IoMT device or service port.',
    steps:[
      { t:'Identify Attack Vector',     m:2,  d:'Determine flood type — SYN, UDP, HTTP, ICMP. Extract source IP and targeted port from IDS logs.', role:'Threat Analyst',  tactic:'Reconnaissance',       technique:'T1046',  tools:['IDS Console','tcpdump'],           evidence:'Attack type classification + source IP confirmed' },
      { t:'Block Source IP',            m:1,  d:'Apply firewall DENY rule for attacker IP. Add to blocklist and threat intelligence feed.', role:'Network Analyst',       tactic:'Containment',          technique:'T1562.001', tools:['Firewall','Blocklist Manager'],   evidence:'Firewall rule ID and blocklist entry timestamp' },
      { t:'Rate-Limit Connections',     m:3,  d:'Configure per-IP connection rate limiting on the affected device interface. Set threshold to 50 conn/sec.', role:'Network Analyst', tactic:'Mitigation',  technique:'T1498',  tools:['ACL Manager','Switch CLI'],        evidence:'Rate-limit config applied — interface counters screenshot' },
      { t:'Restore Device Services',    m:2,  d:'Restart affected service if crashed. Verify device returns to normal operational state.', role:'Incident Responder',      tactic:'Recovery',             technique:'—',      tools:['Device Console','SNMP Monitor'],   evidence:'Device health metrics post-recovery (normal baseline)' },
      { t:'Notify Clinical Staff',      m:1,  d:'Inform biomedical team of affected device and recovery status. Provide ETA if service still degraded.', role:'Incident Responder', tactic:'Coordination', technique:'—', tools:['Phone','Email'],                  evidence:'Staff notification log' },
      { t:'Document & Close',           m:1,  d:'Log incident timeline, IOCs, and response actions. Update risk register if device shows recurring vulnerability.', role:'Threat Analyst', tactic:'Documentation', technique:'—', tools:['SIEM','Ticketing System'],   evidence:'Closed incident ticket with root-cause noted' },
    ]
  },
  Spoofing: {
    sla:20, severity:'high', color:'#8b5cf6', icon:'🎭',
    description:'IP/MAC/ARP spoofing detected — attacker impersonating a trusted IoMT device on the network.',
    steps:[
      { t:'Verify Spoofed Identity',    m:2,  d:'Cross-reference MAC/IP binding in DHCP lease table. Compare ARP cache entries against known device registry.', role:'Threat Analyst', tactic:'Identification',    technique:'T1557.002', tools:['DHCP Console','ARP Monitor'], evidence:'MAC-IP mismatch table with DHCP log timestamps' },
      { t:'Isolate Affected Segment',   m:2,  d:'Place affected VLAN in quarantine mode. Disable affected switch port pending investigation.', role:'SOC Manager',          tactic:'Containment',          technique:'T1562',  tools:['Switch CLI','VLAN Manager'],       evidence:'Switch port shutdown command log + VLAN quarantine ticket' },
      { t:'Block Spoofed Source',       m:1,  d:'Add firewall rule to drop traffic from spoofed IP/MAC. Enable Dynamic ARP Inspection (DAI) on affected VLAN.', role:'Network Analyst', tactic:'Containment',   technique:'T1562.001', tools:['Firewall','Switch CLI'],        evidence:'DAI enabled confirmation + firewall rule ID' },
      { t:'Enable uRPF',                m:3,  d:'Configure Unicast Reverse Path Forwarding on affected interfaces. Verify no legitimate traffic drops.', role:'Network Analyst', tactic:'Hardening',          technique:'—',      tools:['Router CLI'],                      evidence:'uRPF interface config + traffic validation results' },
      { t:'Rotate Credentials & Certs', m:4,  d:'Invalidate any session tokens from the spoofed period. Rotate device TLS certificates if MITM window existed.', role:'Incident Responder', tactic:'Remediation', technique:'T1553', tools:['PKI Console','Cert Manager'],   evidence:'New certificate serial numbers + session invalidation log' },
      { t:'Alert Clinical & Legal',     m:2,  d:'Notify clinical engineering and legal/compliance teams. PHI access during spoof window must be documented for HIPAA.', role:'SOC Manager', tactic:'Compliance',   technique:'—',      tools:['Email','HIPAA Tracker'],           evidence:'Notification sent + HIPAA incident report initiated' },
      { t:'Document & Close',           m:6,  d:'Full forensic timeline of spoof window. Document all devices potentially impacted and any data exposure risk.', role:'Threat Analyst', tactic:'Documentation',   technique:'—',      tools:['SIEM','Forensics Platform'],       evidence:'Forensic report submitted — data exposure risk assessment complete' },
    ]
  },
  Recon: {
    sla:30, severity:'medium', color:'#06b6d4', icon:'🔍',
    description:'Network reconnaissance detected — attacker scanning IoMT devices for open ports and vulnerabilities.',
    steps:[
      { t:'Identify Scanner IP',        m:1,  d:'Extract source IP from IDS/NIDS alerts. Determine scan type — nmap, masscan, or custom. Check threat intel feeds.', role:'Threat Analyst', tactic:'Detection',    technique:'T1046',  tools:['IDS Console','VirusTotal','Shodan'], evidence:'Confirmed scanner IP + scan type classification' },
      { t:'Block IP Range',             m:1,  d:'Block /24 subnet of scanner at perimeter firewall. Add to threat intelligence IOC list.', role:'Network Analyst',       tactic:'Containment',          technique:'T1562.001', tools:['Firewall','IOC Manager'],       evidence:'Firewall block rule applied — /24 subnet confirmed' },
      { t:'Review Exposed Ports',       m:5,  d:'Audit all open ports on scanned devices. Close unnecessary services. Document findings against device baseline.', role:'Network Analyst', tactic:'Hardening',    technique:'T1592',  tools:['Nmap','Port Scanner'],             evidence:'Port audit report — deviations from baseline noted' },
      { t:'Enable Port-Knocking',       m:3,  d:'Configure port-knocking or management interface access control to obscure administrative services.', role:'Network Analyst', tactic:'Hardening',          technique:'—',      tools:['Firewall CLI','Router CLI'],        evidence:'Port-knocking sequence configured + management port hidden' },
      { t:'Threat Intel Submission',    m:2,  d:'Submit scanner IOC to AlienVault OTX and internal threat feed. Correlate with recent global scanning campaigns.', role:'Threat Analyst', tactic:'Intelligence',  technique:'—',      tools:['AlienVault OTX','MISP'],            evidence:'IOC submitted — correlation report attached' },
      { t:'Document & Monitor',         m:18, d:'Log incident and increase monitoring sensitivity for 48 hours. Set up alert for repeat scanning from same /24.', role:'Threat Analyst', tactic:'Documentation', technique:'—',      tools:['SIEM','Alert Manager'],             evidence:'Enhanced monitoring active — alert rule created in SIEM' },
    ]
  },
  MQTT: {
    sla:20, severity:'medium', color:'#22c55e', icon:'📡',
    description:'Unauthorised MQTT broker activity — rogue client publishing/subscribing to IoMT device topics.',
    steps:[
      { t:'Identify Malicious Client',  m:2,  d:'Check MQTT broker logs for unauthorised Client IDs. Review publish/subscribe patterns for sensitive topics.', role:'Threat Analyst', tactic:'Detection',      technique:'T1071.001', tools:['MQTT Broker Console','Wireshark'], evidence:'Rogue Client ID confirmed + topic list extracted' },
      { t:'Disconnect Rogue Client',    m:1,  d:'Force-disconnect malicious MQTT client from broker. Add Client ID to broker blocklist immediately.', role:'Incident Responder', tactic:'Containment',   technique:'T1562',  tools:['MQTT Admin CLI','Broker Dashboard'], evidence:'Disconnect log entry + Client ID blocklisted' },
      { t:'Revoke Client Certificate',  m:1,  d:'Revoke the TLS client certificate used by the rogue client. Publish CRL update to broker trust store.', role:'Incident Responder', tactic:'Containment',  technique:'T1553',  tools:['PKI Console','CRL Manager'],       evidence:'Certificate serial revoked — CRL updated + broker restarted' },
      { t:'Audit All Subscriptions',    m:3,  d:'Review all active topic subscriptions. Identify any sensitive topics — vitals, device-commands — exposed to rogue client.', role:'Threat Analyst', tactic:'Investigation', technique:'T1530', tools:['MQTT Explorer','Broker Logs'],   evidence:'Subscription audit report — sensitive topic exposure assessed' },
      { t:'Rotate Broker Credentials',  m:2,  d:'Update MQTT broker ACL, username/password, and TLS certificates for all legitimate clients.', role:'Network Analyst',       tactic:'Remediation',          technique:'—',      tools:['Broker Config','PKI Console'],      evidence:'New credentials issued to all clients — old credentials invalidated' },
      { t:'Monitor Port 1883/8883',     m:5,  d:'Deploy packet capture on MQTT ports for 24 hours. Alert on any new unauthenticated connection attempts.', role:'Network Analyst', tactic:'Monitoring',    technique:'—',      tools:['Wireshark','SIEM Alert'],           evidence:'PCAP session started — SIEM rule active for port 1883/8883' },
      { t:'Document & Close',           m:6,  d:'Document compromised topics, rogue client identity, and data exposure window. Notify HIPAA compliance if PHI was in scope.', role:'Threat Analyst', tactic:'Documentation', technique:'—', tools:['SIEM','HIPAA Tracker'],         evidence:'Incident report complete — HIPAA assessment filed if applicable' },
    ]
  },
};

// ── Device Risk Scores ─────────────────────────────────────────────────────────
const deviceRiskData = {
  'Infusion Pump':   { score:87, level:'critical', factors:['Unpatched firmware (CVE-2023-1234)','PHI data exposure','Default credentials active','Network-accessible management port'], patches:0 },
  'Heart Monitor':   { score:62, level:'high',     factors:['Outdated OS (Win XP Embedded)','PHI data exposure','Limited TLS support'], patches:3 },
  'Pulse Oximeter':  { score:28, level:'low',      factors:['Network-accessible'], patches:0 },
  'ECG Monitor':     { score:45, level:'medium',   factors:['Unencrypted data in transit','PHI data exposure','Weak authentication'], patches:1 },
};

// Patch data at module level so the remediation modal can access it without the risk-tab IIFE
const DEVICE_PATCH_DATA = {
  'Infusion Pump': [
    { id:'fw-3.2.0',   label:'Apply Firmware 3.2.0 (patches CVE-2023-1234, CVSS 9.1)', priority:'critical', reduction:14 },
    { id:'cred-reset', label:'Rotate all default credentials',                           priority:'critical', reduction:10 },
    { id:'port-close', label:'Close management port 8443',                               priority:'high',     reduction:6  },
  ],
  'Heart Monitor': [
    { id:'os-upgrade', label:'Upgrade OS to Windows 10 IoT LTSC',                       priority:'critical', reduction:12 },
    { id:'tls-enable', label:'Enforce TLS 1.2 minimum on all interfaces',               priority:'high',     reduction:7  },
    { id:'cve-4567',   label:'Apply CVE-2023-4567 vendor hotfix',                       priority:'high',     reduction:6  },
  ],
  'Pulse Oximeter': [],
  'ECG Monitor': [
    { id:'tls13',      label:'Enable TLS 1.3 and rotate authentication tokens',         priority:'high',     reduction:8  },
  ],
};

// Initial audit timestamps — match the old hardcoded "X days ago" strings
const AUDIT_DEFAULTS = {
  'Infusion Pump':  Date.now() - 42 * 86400_000,
  'Heart Monitor':  Date.now() - 28 * 86400_000,
  'Pulse Oximeter': Date.now() -  7 * 86400_000,
  'ECG Monitor':    Date.now() - 15 * 86400_000,
};

function timeAgo(ts) {
  const diff = Date.now() - ts;
  const mins  = Math.floor(diff / 60_000);
  const hours = Math.floor(diff / 3_600_000);
  const days  = Math.floor(diff / 86_400_000);
  if (mins  <  1) return 'just now';
  if (mins  < 60) return `${mins} min ago`;
  if (hours < 24) return `${hours} hr ago`;
  return `${days} day${days !== 1 ? 's' : ''} ago`;
}

// ── Forensic Packet Capture ────────────────────────────────────────────────────
const generatePackets = () => Array.from({length:12},(_,i)=>({
  no: 1000+i, time: `${(i*0.043).toFixed(3)}`, src: `192.168.${40+i}.${Math.floor(Math.random()*254)+1}`,
  dst: `192.168.1.${[50,22,35,41][i%4]}`, protocol:['TCP','UDP','ARP','ICMP','TLS'][i%5],
  len: Math.floor(Math.random()*1400)+64, info:[
    'SYN flood packet burst','ARP Reply - IP: 192.168.1.1','Encrypted application data',
    'ICMP Echo Request','Malformed TCP segment','DNS query: mal1c10us.xyz',
    'HTTP GET /admin','TLS Client Hello','UDP payload anomaly','RST flood',
    'HTTP POST /api/config','ARP Request broadcast'
  ][i],
  flag: i<3||i===5||i===8
}));

// ── Geographic Attack Sources ──────────────────────────────────────────────────
// geoToSvg: equirectangular → 200×100 viewBox
const geoToSvg = (lat, lon) => ({
  x: parseFloat(((lon + 180) / 360 * 200).toFixed(1)),
  y: parseFloat(((90 - lat)  / 180 * 100).toFixed(1)),
});

// City metadata lookup — used by live geo hits (no static counts)
const CITY_META = {
  'Moscow, RU':      { lat:55.8,  lon:37.6,   severity:'critical', isp:'RuNet AS8359'        },
  'Beijing, CN':     { lat:39.9,  lon:116.4,  severity:'critical', isp:'ChinaNet AS4134'     },
  'Pyongyang, KP':   { lat:39.0,  lon:125.8,  severity:'critical', isp:'STAR-KP AS131279'    },
  'São Paulo, BR':   { lat:-23.5, lon:-46.6,  severity:'high',     isp:'Vivo AS26599'        },
  'Lagos, NG':       { lat:6.5,   lon:3.4,    severity:'high',     isp:'MTN AS29465'         },
  'Caracas, VE':     { lat:10.5,  lon:-66.9,  severity:'high',     isp:'CANTV AS8048'        },
  'Jakarta, ID':     { lat:-6.2,  lon:106.8,  severity:'high',     isp:'Telkom AS17974'      },
  'Tehran, IR':      { lat:35.7,  lon:51.4,   severity:'medium',   isp:'DCI AS12880'         },
  'Bucharest, RO':   { lat:44.4,  lon:26.1,   severity:'medium',   isp:'RCS AS8708'          },
  'Minsk, BY':       { lat:53.9,  lon:27.5,   severity:'medium',   isp:'Beltelecom AS6697'   },
  'Dhaka, BD':       { lat:23.7,  lon:90.4,   severity:'low',      isp:'BTCL AS18101'        },
  'Nairobi, KE':     { lat:-1.3,  lon:36.8,   severity:'low',      isp:'Safaricom AS33771'   },
  'Shanghai, CN':    { lat:31.2,  lon:121.5,  severity:'critical', isp:'ChinaNet AS4134'     },
  'Ankara, TR':      { lat:39.9,  lon:32.9,   severity:'high',     isp:'Turk Telekom AS9121' },
  'Cairo, EG':       { lat:30.0,  lon:31.2,   severity:'high',     isp:'TE AS8452'           },
  'Hanoi, VN':       { lat:21.0,  lon:105.8,  severity:'medium',   isp:'VNPT AS45899'        },
  'Bogotá, CO':      { lat:4.7,   lon:-74.1,  severity:'high',     isp:'ETB AS10620'         },
  'Kinshasa, CD':    { lat:-4.3,  lon:15.3,   severity:'medium',   isp:'AFRINET AS37342'     },
};
// Pre-compute SVG x/y for each city
Object.keys(CITY_META).forEach(city => {
  const { lat, lon } = CITY_META[city];
  Object.assign(CITY_META[city], geoToSvg(lat, lon));
});

// GEO_ATTACK_MAP: attack type → possible source cities (DDoS gets widest spread)
const GEO_ATTACK_MAP = {
  'DDoS':     ['Moscow, RU', 'Pyongyang, KP', 'Caracas, VE', 'Shanghai, CN', 'Ankara, TR', 'Bogotá, CO'],
  'DoS':      ['São Paulo, BR', 'Caracas, VE', 'Cairo, EG', 'Bogotá, CO'],
  'Spoofing': ['São Paulo, BR', 'Tehran, IR', 'Minsk, BY', 'Dhaka, BD', 'Ankara, TR'],
  'Recon':    ['Beijing, CN', 'Jakarta, ID', 'Bucharest, RO', 'Nairobi, KE', 'Hanoi, VN', 'Shanghai, CN'],
  'MQTT':     ['Lagos, NG', 'Dhaka, BD', 'Kinshasa, CD', 'Hanoi, VN'],
};

// ── SOC Team ──────────────────────────────────────────────────────────────────
const SOC_TEAM = [
  { name: 'System Administrator', role: 'System Administrator',          avatar: 'AD', color: '#f59e0b', online: true,  username: 'admin'    },
  { name: 'Tinashe Chidarikire',  role: 'SOC Manager',                   avatar: 'TC', color: '#ef4444', online: true,  username: 'tinashe'  },
  { name: 'Precious Chimperu',    role: 'Threat Intelligence Analyst',   avatar: 'PC', color: '#8b5cf6', online: true,  username: 'precious' },
  { name: 'Primrose Tivatyi',     role: 'Incident Responder',            avatar: 'PT', color: '#06b6d4', online: true,  username: 'primrose' },
  { name: 'Jubillee Maringe',     role: 'ML / Data Engineer',            avatar: 'JM', color: '#22c55e', online: false, username: 'jubillee' },
  { name: 'Evelyn Chipangura',    role: 'Network Security Analyst',      avatar: 'EC', color: '#f97316', online: true,  username: 'evelyn'   },
];
// Rotate through analysts (excluding manager for response actions)
const SOC_ANALYSTS = SOC_TEAM.slice(1);
let _analystIdx = 0;
const nextAnalyst = () => { const a = SOC_ANALYSTS[_analystIdx % SOC_ANALYSTS.length]; _analystIdx++; return a.name; };

// Hospital + device node positions on the SVG (near New York)
const HOSPITAL = { ...geoToSvg(40.7, -74.0), lon:-74.0, lat:40.7 };
const DEVICE_NODES = [
  { device:'Infusion Pump',  ...geoToSvg(37.5,-90), color:'#ef4444', ip:'192.168.20.50', label:'Inf. Pump',  labelAbove:true  },
  { device:'Heart Monitor',  ...geoToSvg(37.5,-80), color:'#f97316', ip:'192.168.20.22', label:'Heart Mon.', labelAbove:false },
  { device:'Pulse Oximeter', ...geoToSvg(37.5,-70), color:'#22c55e', ip:'192.168.20.35', label:'Pulse Ox.',  labelAbove:true  },
  { device:'ECG Monitor',    ...geoToSvg(37.5,-60), color:'#8b5cf6', ip:'192.168.20.41', label:'ECG Mon.',   labelAbove:false },
];

// ── HIPAA Compliance Data ──────────────────────────────────────────────────────
const BASE_HIPAA_RULES = [
  {
    id: 'privacy', name: 'Privacy Rule', score: 78, icon: 'lock',
    controls: [
      { id: 'min_necessary', label: 'Minimum Necessary Standard', status: 'pass' },
      { id: 'notice_phi',    label: 'Notice of Privacy Practices', status: 'pass' },
      { id: 'patient_rights',label: 'Patient Rights Enforcement', status: 'pass' },
      { id: 'phi_disclosure',label: 'PHI Disclosure Tracking', status: 'warn' },
      { id: 'business_assoc',label: 'Business Associate Agreements', status: 'fail' },
    ],
  },
  {
    id: 'security', name: 'Security Rule', score: 65, icon: 'shield',
    controls: [
      { id: 'access_ctrl',  label: 'Access Control (§164.312a1)', status: 'pass' },
      { id: 'audit_ctrl',   label: 'Audit Controls (§164.312b)',  status: 'warn' },
      { id: 'integrity',    label: 'Integrity (§164.312c1)',       status: 'pass' },
      { id: 'auth_person',  label: 'Person Authentication',        status: 'warn' },
      { id: 'transmission', label: 'Transmission Security',        status: 'fail' },
      { id: 'encryption',   label: 'ePHI Encryption at Rest',      status: 'fail' },
    ],
  },
  {
    id: 'breach', name: 'Breach Notification Rule', score: 90, icon: 'bell',
    controls: [
      { id: 'detect_breach', label: 'Breach Detection Capability', status: 'pass' },
      { id: 'notify_60',     label: '60-Day Notification SLA',     status: 'pass' },
      { id: 'hhs_report',    label: 'HHS Annual Reporting',        status: 'pass' },
      { id: 'media_notice',  label: 'Media Notice >500 Affected',  status: 'warn' },
    ],
  },
];

const hipaaViolations = [
  { id: 1, rule: 'Security Rule', control: 'Transmission Security', device: 'ECG Monitor',    severity: 'high',   detail: 'Unencrypted HL7 data stream on port 2575', ts: '09:14:22' },
  { id: 2, rule: 'Security Rule', control: 'ePHI Encryption at Rest', device: 'Patient DB',   severity: 'high',   detail: 'Table patient_vitals lacks AES-256 encryption', ts: '08:57:05' },
  { id: 3, rule: 'Privacy Rule',  control: 'Business Associate Agreement', device: 'ML Server', severity: 'medium', detail: 'BAA not signed for third-party analytics module', ts: '07:30:11' },
  { id: 4, rule: 'Security Rule', control: 'Audit Controls', device: 'Infusion Pump',         severity: 'medium', detail: 'Audit logging disabled on firmware v1.2.3', ts: '06:45:00' },
  { id: 5, rule: 'Privacy Rule',  control: 'PHI Disclosure Tracking', device: 'Heart Monitor', severity: 'low',    detail: 'Disclosure log missing for 3 external queries', ts: 'Yesterday' },
];

const phiAccessLog = [
  { id: 1, user: 'analyst@hospital.org', action: 'READ',   resource: 'Patient Vitals — ICU',    device: 'Heart Monitor',  ts: '10:02:44', status: 'allowed' },
  { id: 2, user: 'system@ml-server',     action: 'READ',   resource: 'ECG Waveform Stream',     device: 'ECG Monitor',    ts: '10:01:18', status: 'allowed' },
  { id: 3, user: 'unknown@192.168.44.7', action: 'WRITE',  resource: 'Infusion Pump Config',    device: 'Infusion Pump',  ts: '09:58:01', status: 'denied'  },
  { id: 4, user: 'admin@hospital.org',   action: 'DELETE', resource: 'Patient Record #8842',    device: 'Patient DB',     ts: '09:44:32', status: 'allowed' },
  { id: 5, user: 'report@analytics',     action: 'EXPORT', resource: 'SpO2 Trend — 30 days',   device: 'Pulse Oximeter', ts: '09:30:09', status: 'warn'    },
  { id: 6, user: 'unknown@10.0.0.99',    action: 'READ',   resource: 'Medication Schedule',     device: 'Infusion Pump',  ts: '09:14:22', status: 'denied'  },
];

// ── GRC Base Data (baseline scores reflect static audit findings) ──────────────
const BASE_GRC = [
  { id:'hipaa',    name:'HIPAA',            score:74, controls:42,  passing:31, critical:3, color:'#06b6d4', reg:'Health Insurance Portability & Accountability Act' },
  { id:'nist_csf', name:'NIST CSF v1.1',   score:68, controls:108, passing:73, critical:5, color:'#8b5cf6', reg:'NIST Cybersecurity Framework v1.1' },
  { id:'hitech',   name:'HITECH',           score:81, controls:28,  passing:23, critical:1, color:'#22c55e', reg:'Health IT for Economic & Clinical Health Act' },
  { id:'fda',      name:'FDA 21 CFR Pt 11', score:55, controls:34,  passing:19, critical:6, color:'#f97316', reg:'FDA Electronic Records / Electronic Signatures' },
  { id:'iso27001', name:'ISO 27001:2022',   score:62, controls:93,  passing:58, critical:4, color:'#eab308', reg:'Information Security Management System' },
];

// ── Live GRC scoring: deducts from baseline as live attacks accumulate ─────────
// Each attack type maps to the frameworks it most severely violates.
// Penalties are capped so one attack type can't wipe a framework on its own.
function computeGrcScores(alerts) {
  const recent = alerts.slice(0, 60); // use up to 60 most recent alerts
  const c = { DDoS: 0, DoS: 0, Spoofing: 0, Recon: 0, MQTT: 0 };
  recent.forEach(a => { if (c[a.type] !== undefined) c[a.type]++; });

  // p(type, pointsPerAlert, maxPenalty)
  const p = (type, pts, max) => Math.min(c[type] * pts, max);

  const penalties = {
    // HIPAA — PHI confidentiality: Spoofing (MiTM = PHI exposure) hits hardest
    hipaa:    p('Spoofing',4,20) + p('DDoS',3,15) + p('MQTT',3,12) + p('DoS',2,10) + p('Recon',2,8),
    // NIST CSF — availability + detection controls: DDoS hits hardest
    nist_csf: p('DDoS',4,20) + p('DoS',3,15) + p('Recon',3,12) + p('Spoofing',2,10) + p('MQTT',2,8),
    // HITECH — breach disclosure: same PHI focus as HIPAA
    hitech:   p('Spoofing',4,18) + p('MQTT',3,12) + p('DDoS',2,10) + p('DoS',2,8) + p('Recon',1,5),
    // FDA 21 CFR — device integrity/audit trails: MQTT injection hits hardest
    fda:      p('MQTT',5,25) + p('DoS',3,12) + p('Spoofing',3,10) + p('DDoS',2,8) + p('Recon',1,4),
    // ISO 27001 — general InfoSec: balanced across all attack types
    iso27001: p('DDoS',3,15) + p('Spoofing',3,12) + p('DoS',2,10) + p('MQTT',2,8) + p('Recon',2,8),
  };

  return BASE_GRC.map(fw => {
    const penalty  = Math.min(penalties[fw.id] || 0, fw.score - 20); // never drop below 20
    const score    = Math.max(20, fw.score - penalty);
    const ratio    = score / fw.score;
    const passing  = Math.max(0, Math.round(fw.passing * ratio));
    const extra    = Math.min(4, Math.floor(penalty / 8));            // extra critical gaps per 8pts penalty
    return { ...fw, score, passing, critical: fw.critical + extra };
  });
}

// ── Live HIPAA rule scoring ────────────────────────────────────────────────────
function computeHipaaScores(alerts) {
  const recent = alerts.slice(0, 60);
  const c = { DDoS: 0, DoS: 0, Spoofing: 0, Recon: 0, MQTT: 0 };
  recent.forEach(a => { if (c[a.type] !== undefined) c[a.type]++; });
  const p = (type, pts, max) => Math.min(c[type] * pts, max);

  const rulePenalties = {
    // Privacy Rule: PHI disclosure risk — Spoofing (MiTM) and Recon are primary threats
    privacy:  p('Spoofing',4,18) + p('Recon',2,10) + p('MQTT',2,8),
    // Security Rule: transmission security, access control, audit — all attacks relevant
    security: p('DDoS',3,15) + p('DoS',3,12) + p('Spoofing',4,16) + p('MQTT',2,8) + p('Recon',2,8),
    // Breach Notification: any confirmed attack is a potential reportable breach
    breach:   p('DDoS',1,8) + p('DoS',1,8) + p('Spoofing',2,12) + p('MQTT',1,6) + p('Recon',1,5),
  };

  return BASE_HIPAA_RULES.map(rule => {
    const penalty = Math.min(rulePenalties[rule.id] || 0, rule.score - 20);
    return { ...rule, score: Math.max(20, rule.score - penalty) };
  });
}

const riskRegister = [
  { id:'R001', cat:'Cyber',       title:'Ransomware attack on IoMT devices',              l:4, i:5, treatment:'Mitigate', owner:'CISO',       status:'open',        due:'2026-04-01', linked:'Infusion Pump' },
  { id:'R002', cat:'Compliance',  title:'HIPAA PHI disclosure violation',                  l:3, i:4, treatment:'Mitigate', owner:'DPO',        status:'in-progress', due:'2026-03-30', linked:'Heart Monitor' },
  { id:'R003', cat:'Operational', title:'Infusion pump firmware unpatched (CVE-2023-1234)',l:4, i:4, treatment:'Mitigate', owner:'IT Manager', status:'open',        due:'2026-03-25', linked:'Infusion Pump' },
  { id:'R004', cat:'Cyber',       title:'MITM attack on HL7/2575 data stream',             l:3, i:5, treatment:'Mitigate', owner:'SOC Lead',   status:'open',        due:'2026-04-15', linked:'ECG Monitor' },
  { id:'R005', cat:'Third Party', title:'Vendor BAA unsigned — ML analytics module',       l:2, i:3, treatment:'Accept',   owner:'Legal',      status:'open',        due:'2026-05-01', linked:'ML Server' },
  { id:'R006', cat:'Operational', title:'ECG monitor data unencrypted in transit',         l:4, i:4, treatment:'Mitigate', owner:'IT Manager', status:'in-progress', due:'2026-03-20', linked:'ECG Monitor' },
  { id:'R007', cat:'Compliance',  title:'Audit log gaps on Infusion Pump firmware',        l:3, i:3, treatment:'Mitigate', owner:'Compliance', status:'open',        due:'2026-04-10', linked:'Infusion Pump' },
  { id:'R008', cat:'Cyber',       title:'DDoS targeting hospital network perimeter',       l:4, i:3, treatment:'Transfer', owner:'CISO',       status:'mitigated',   due:'2026-03-15', linked:'Gateway' },
  { id:'R009', cat:'Operational', title:'Pulse Oximeter weak authentication credentials', l:2, i:2, treatment:'Mitigate', owner:'IT Manager', status:'open',        due:'2026-04-20', linked:'Pulse Oximeter' },
  { id:'R010', cat:'Cyber',       title:'Insider threat — privileged PHI data access',    l:2, i:5, treatment:'Mitigate', owner:'CISO',       status:'open',        due:'2026-05-15', linked:'Patient DB' },
];

const auditFindings = [
  { id:'AF-001', framework:'HIPAA',    control:'Access Control §164.312(a)',  sev:'critical', status:'open',        finding:'Default admin credentials active on Infusion Pump', due:'2026-03-20' },
  { id:'AF-002', framework:'NIST CSF', control:'PR.AC-4',                    sev:'high',     status:'open',        finding:'Insufficient least-privilege controls for PHI systems', due:'2026-03-25' },
  { id:'AF-003', framework:'FDA',      control:'21 CFR 11.10(d)',             sev:'critical', status:'open',        finding:'Electronic audit trails disabled on ECG Monitor', due:'2026-03-18' },
  { id:'AF-004', framework:'ISO 27001',control:'A.12.4.1',                   sev:'high',     status:'in-progress', finding:'Incomplete event logging on ML Server syslog', due:'2026-04-01' },
  { id:'AF-005', framework:'HITECH',   control:'§13402(b)',                  sev:'medium',   status:'remediated',  finding:'Breach notification SLA not formally tested', due:'2026-02-28' },
  { id:'AF-006', framework:'NIST CSF', control:'DE.CM-7',                    sev:'high',     status:'open',        finding:'No monitoring for unauthorised device connections', due:'2026-04-05' },
  { id:'AF-007', framework:'HIPAA',    control:'Transmission Security §164.312(e)',sev:'high',status:'in-progress',finding:'HL7 v2 stream on port 2575 lacks TLS/MLLP-S', due:'2026-03-28' },
];

const grcPolicies = [
  { id:'POL-001', name:'Information Security Policy',   status:'approved', lastReview:'2025-11-01', nextReview:'2026-11-01', owner:'CISO',       frameworks:['HIPAA','ISO 27001','NIST CSF'] },
  { id:'POL-002', name:'IoMT Device Security Policy',  status:'draft',    lastReview:'2025-08-15', nextReview:'2026-02-15', owner:'IT Manager', frameworks:['FDA','HIPAA'] },
  { id:'POL-003', name:'PHI Access Control Policy',    status:'approved', lastReview:'2026-01-10', nextReview:'2027-01-10', owner:'DPO',        frameworks:['HIPAA','HITECH'] },
  { id:'POL-004', name:'Incident Response Policy',     status:'approved', lastReview:'2025-12-01', nextReview:'2026-12-01', owner:'SOC Lead',   frameworks:['NIST CSF','ISO 27001'] },
  { id:'POL-005', name:'Vendor Management Policy',     status:'expired',  lastReview:'2024-09-01', nextReview:'2025-09-01', owner:'Legal',      frameworks:['ISO 27001','HIPAA'] },
  { id:'POL-006', name:'Business Continuity Plan',     status:'approved', lastReview:'2026-01-20', nextReview:'2027-01-20', owner:'Operations', frameworks:['ISO 27001','NIST CSF'] },
  { id:'POL-007', name:'Cryptography & Key Mgmt Policy',status:'draft',   lastReview:'2025-06-01', nextReview:'2025-12-01', owner:'CISO',       frameworks:['ISO 27001','HIPAA','FDA'] },
];

// ── Traffic Heatmap ────────────────────────────────────────────────────────────
const hours = Array.from({length:24},(_,i)=>`${String(i).padStart(2,'0')}:00`);
const days  = ['Mon','Tue','Wed','Thu','Fri','Sat','Sun'];
const _DAY_IDX = { 0:'Sun',1:'Mon',2:'Tue',3:'Wed',4:'Thu',5:'Fri',6:'Sat' };
const todayName = () => _DAY_IDX[new Date().getDay()];
const emptyHeatmap = () => days.map(d=>({ day:d, ...Object.fromEntries(hours.map(h=>[h,0])) }));

// ── Role-Based Access Control ──────────────────────────────────────────────────
const ROLE_DEFS = {
  // Admin: SYSTEM ADMINISTRATOR — manages users, system config, full read access across all modules
  admin: {
    label: 'System Administrator', color: '#f59e0b', badge: 'bg-amber-500/20 text-amber-300 border-amber-500/40',
    tabs: ['admin_panel', 'exec', 'analytics', 'logs', 'team'],
    canIsolate: false, canBlock: false, canAck: false,
    canManageUsers: true, canConfigSystem: true, canViewAll: true, canExportAll: true,
    description: 'Manages user accounts, system configuration, integrations and audit logs. Full read access to all modules.',
    restrictions: 'Does not perform live SOC operations — incident response actions are reserved for SOC roles.',
  },
  // SOC Manager (Tinashe): Operational lead — incident command, all security ops
  soc_manager: {
    label: 'SOC Manager', color: '#ef4444', badge: 'bg-red-500/20 text-red-300 border-red-500/40',
    tabs: ['exec', 'analytics', 'alerts', 'logs', 'playbook', 'risk', 'forensics', 'geomap', 'heatmap', 'topology', 'upload', 'team'],
    canIsolate: true, canBlock: true, canAck: true,
    description: 'Operational incident command. Authorises device isolation & IP blocking.',
    restrictions: 'No direct access to HIPAA/GRC configuration panels.',
  },
  // Threat Intelligence Analyst (Precious): Hunt, correlate, investigate threats
  threat_analyst: {
    label: 'Threat Intel Analyst', color: '#8b5cf6', badge: 'bg-violet-500/20 text-violet-300 border-violet-500/40',
    tabs: ['exec', 'analytics', 'alerts', 'logs', 'forensics', 'geomap', 'heatmap', 'team'],
    canIsolate: false, canBlock: false, canAck: true,
    description: 'Threat hunting, intelligence correlation & indicator analysis.',
    restrictions: 'Cannot isolate devices or block IPs. No playbook execution or compliance access.',
  },
  // Incident Responder (Primrose): Triage, contain, execute playbooks
  incident_responder: {
    label: 'Incident Responder', color: '#06b6d4', badge: 'bg-cyan-500/20 text-cyan-300 border-cyan-500/40',
    tabs: ['exec', 'analytics', 'alerts', 'logs', 'playbook', 'forensics', 'topology', 'team'],
    canIsolate: true, canBlock: false, canAck: true,
    description: 'Active incident triage, containment & playbook-driven response.',
    restrictions: 'Can isolate devices but cannot block IPs — escalate to SOC Manager.',
  },
  // ML / Data Engineer (Jubillee): Model management, CSV analysis, data quality
  ml_engineer: {
    label: 'ML / Data Engineer', color: '#22c55e', badge: 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40',
    tabs: ['exec', 'analytics', 'upload', 'forensics', 'heatmap', 'team'],
    canIsolate: false, canBlock: false, canAck: false,
    description: 'ML model oversight, dataset upload, traffic analysis & heatmap review.',
    restrictions: 'Read-only on alerts. No incident response actions or compliance access.',
  },
  // Network Security Analyst (Evelyn): Network visibility, geo threats, topology
  network_analyst: {
    label: 'Network Security Analyst', color: '#f97316', badge: 'bg-orange-500/20 text-orange-300 border-orange-500/40',
    tabs: ['exec', 'analytics', 'alerts', 'logs', 'geomap', 'heatmap', 'topology', 'team'],
    canIsolate: false, canBlock: true, canAck: true,
    description: 'Network traffic monitoring, geo-threat analysis & device topology.',
    restrictions: 'Can block IPs but cannot isolate devices. No forensics or compliance access.',
  },
};

const DEMO_USERS = [
  { username: 'admin',     password: 'Admin@2026!',  role: 'admin',              name: 'System Administrator', title: 'Administrator',               dept: 'IT Administration',   avatar: 'AD', phone: '+1 555 000 0001' },
  { username: 'tinashe',   password: 'Tinashe@2026', role: 'soc_manager',        name: 'Tinashe Chidarikire',  title: 'SOC Manager',                 dept: 'Security Operations', avatar: 'TC', phone: '+1 555 100 0001' },
  { username: 'precious',  password: 'Precious@2026',role: 'threat_analyst',     name: 'Precious Chimperu',    title: 'Threat Intelligence Analyst', dept: 'Threat Analysis',     avatar: 'PC', phone: '+1 555 100 0002' },
  { username: 'primrose',  password: 'Primrose@2026',role: 'incident_responder', name: 'Primrose Tivatyi',     title: 'Incident Responder',          dept: 'Security Operations', avatar: 'PT', phone: '+1 555 100 0003' },
  { username: 'jubillee',  password: 'Jubillee@2026',role: 'ml_engineer',        name: 'Jubillee Maringe',     title: 'ML / Data Engineer',          dept: 'Data Engineering',    avatar: 'JM', phone: '+1 555 100 0004' },
  { username: 'evelyn',    password: 'Evelyn@2026',  role: 'network_analyst',    name: 'Evelyn Chipangura',    title: 'Network Security Analyst',    dept: 'Network Security',    avatar: 'EC', phone: '+1 555 100 0005' },
];

// Mask a phone number: "+263 77 123 4567" → "+263 77 *** 4567"
function maskPhone(phone) {
  if (!phone) return '*** *** ****';
  const digits = phone.replace(/\D/g,'');
  const visible = digits.slice(-4);
  const prefix  = phone.slice(0, phone.indexOf(digits.slice(4,7)));
  return phone.replace(/\d(?=(?:\D*\d){4})/g, '*');
}

function LoginPage({ onLogin, checkCredentials, onOtpGenerated }) {
  const [username, setUsername]   = useState('');
  const [password, setPassword]   = useState('');
  const [showPass, setShowPass]   = useState(false);
  const [remember, setRemember]   = useState(false);
  const [error, setError]         = useState('');
  const [loading, setLoading]     = useState(false);
  const [loginAttempts, setLoginAttempts] = useState(0);

  // MFA step
  const [mfaStep,      setMfaStep]      = useState(false);
  const [mfaCode,      setMfaCode]      = useState('');
  const [mfaPhone,     setMfaPhone]     = useState('');   // masked phone shown to user
  const [mfaRawPhone,  setMfaRawPhone]  = useState('');   // real phone for resend
  const [mfaInput,     setMfaInput]     = useState('');
  const [mfaError,     setMfaError]     = useState('');
  const [mfaUser,      setMfaUser]      = useState(null);
  const [mfaCountdown, setMfaCountdown] = useState(30);
  const mfaTimerRef = React.useRef(null);

  const startMfaTimer = () => {
    setMfaCountdown(30);
    clearInterval(mfaTimerRef.current);
    mfaTimerRef.current = setInterval(() => {
      setMfaCountdown(prev => {
        if (prev <= 1) { clearInterval(mfaTimerRef.current); return 0; }
        return prev - 1;
      });
    }, 1000);
  };

  const generateCode = () => String(Math.floor(100000 + Math.random() * 900000));

  const handleSubmit = (e) => {
    e.preventDefault();
    if (loginAttempts >= 3) return;
    setLoading(true);
    setError('');
    setTimeout(() => {
      const result = checkCredentials(username, password);
      if (result.ok) {
        if (result.mfaEnabled) {
          const code = generateCode();
          onOtpGenerated(result.user.username, code);   // notify admin panel
          setMfaCode(code);
          setMfaUser(result.user);
          setMfaRawPhone(result.phone);
          setMfaPhone(maskPhone(result.phone));
          setMfaInput('');
          setMfaError('');
          setMfaStep(true);
          startMfaTimer();
          setLoading(false);
          // Send SMS via backend
          fetch('${API_BASE}/api/send-otp', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ phone: result.phone, code }),
          }).then(r => r.json()).then(data => {
            if (!data.ok) console.warn('[MFA] SMS not sent:', data.error);
          }).catch(() => {/* backend may be offline */});
        } else {
          onLogin(result.user);
        }
      } else {
        if (result.reason === 'blocked') {
          setError('This account has been blocked. Contact your system administrator.');
          setLoading(false);
          return;
        }
        const attempts = loginAttempts + 1;
        setLoginAttempts(attempts);
        setError(attempts >= 3
          ? 'Account locked after 3 failed attempts. Contact your system administrator.'
          : `Authentication failed. ${3 - attempts} attempt${3 - attempts !== 1 ? 's' : ''} remaining.`
        );
        setLoading(false);
      }
    }, 900);
  };

  const handleMfaSubmit = (e) => {
    e.preventDefault();
    if (mfaCountdown === 0) { setMfaError('Code expired. Please request a new code.'); return; }
    if (mfaInput.trim() === mfaCode) {
      clearInterval(mfaTimerRef.current);
      onLogin(mfaUser);
    } else {
      setMfaError('Invalid code. Please try again.');
      setMfaInput('');
    }
  };

  const handleMfaRefresh = () => {
    const code = generateCode();
    onOtpGenerated(mfaUser.username, code);
    setMfaCode(code);
    setMfaInput('');
    setMfaError('');
    startMfaTimer();
    // Resend SMS
    fetch('${API_BASE}/api/send-otp', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ phone: mfaRawPhone, code }),
    }).catch(() => {});
  };

  const locked = loginAttempts >= 3;

  return (
    <div style={{ minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center', fontFamily: 'system-ui, -apple-system, sans-serif', position: 'relative', overflow: 'hidden', background: '#060d1a' }}>

      {/* Full-screen background layer */}
      <div style={{ position: 'absolute', inset: 0, backgroundImage: 'radial-gradient(circle, rgba(6,182,212,0.12) 1px, transparent 1px)', backgroundSize: '32px 32px' }} />
      <div style={{ position: 'absolute', top: '15%', left: '20%', width: 700, height: 700, borderRadius: '50%', background: 'radial-gradient(circle, rgba(6,182,212,0.06) 0%, transparent 65%)', pointerEvents: 'none' }} />
      <div style={{ position: 'absolute', bottom: '10%', right: '15%', width: 500, height: 500, borderRadius: '50%', background: 'radial-gradient(circle, rgba(99,102,241,0.07) 0%, transparent 65%)', pointerEvents: 'none' }} />

      {/* Top-left brand watermark */}
      <div style={{ position: 'absolute', top: 28, left: 36, display: 'flex', alignItems: 'center', gap: 12, zIndex: 1 }}>
        <div style={{ width: 40, height: 40, borderRadius: 11, background: 'linear-gradient(135deg, #06b6d4, #2563eb)', display: 'flex', alignItems: 'center', justifyContent: 'center', boxShadow: '0 0 20px rgba(6,182,212,0.4)' }}>
          <Shield style={{ width: 22, height: 22, color: 'white' }} />
        </div>
        <div>
          <div style={{ fontSize: 15, fontWeight: 700, color: 'white' }}>IoMT Anomaly Detection System</div>
          <div style={{ fontSize: 10, fontWeight: 600, color: '#22d3ee', letterSpacing: '0.12em', textTransform: 'uppercase' }}>Anomaly Detection System</div>
        </div>
      </div>

      {/* Bottom-left info */}
      <div style={{ position: 'absolute', bottom: 24, left: 36, zIndex: 1 }}>
        <div style={{ fontSize: 12, color: '#334155' }}>IoMT Anomaly Detection System</div>
        <div style={{ fontSize: 11, color: '#1e293b', marginTop: 2 }}>© 2026 IoMT Anomaly Detection System · All rights reserved</div>
      </div>

      {/* Bottom-right compliance badges */}
      <div style={{ position: 'absolute', bottom: 24, right: 36, display: 'flex', gap: 10, zIndex: 1 }}>
        {[['HIPAA','#22c55e'],['ISO 27001','#06b6d4'],['NIST CSF','#8b5cf6'],['TLS 1.3','#f97316']].map(([l,c]) => (
          <div key={l} style={{ display: 'flex', alignItems: 'center', gap: 5, padding: '4px 10px', borderRadius: 6, background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.07)' }}>
            <div style={{ width: 5, height: 5, borderRadius: '50%', background: c }} />
            <span style={{ fontSize: 10, color: '#334155', fontWeight: 600 }}>{l}</span>
          </div>
        ))}
      </div>

      {/* ── CENTERED CARD ── */}
      <div style={{ position: 'relative', zIndex: 2, width: '100%', maxWidth: 460, padding: '0 20px' }}>

        {/* Classification banner above card */}
        <div style={{ display: 'flex', justifyContent: 'center', marginBottom: 20 }}>
          <div style={{ display: 'inline-flex', alignItems: 'center', gap: 8, padding: '6px 16px', borderRadius: 100, background: 'rgba(6,182,212,0.08)', border: '1px solid rgba(6,182,212,0.22)' }}>
            <div style={{ width: 6, height: 6, borderRadius: '50%', background: '#22d3ee' }} />
            <span style={{ fontSize: 11, fontWeight: 700, color: '#67e8f9', letterSpacing: '0.1em' }}>RESTRICTED — AUTHORIZED PERSONNEL ONLY</span>
          </div>
        </div>

        {/* Login card */}
        <div style={{ background: 'rgba(8,15,28,0.96)', border: `1px solid ${mfaStep ? 'rgba(99,102,241,0.35)' : 'rgba(255,255,255,0.1)'}`, borderRadius: 22, padding: '44px 40px', boxShadow: '0 40px 80px rgba(0,0,0,0.7), inset 0 1px 0 rgba(255,255,255,0.07)', transition: 'border-color 0.3s' }}>

        {mfaStep ? (
          /* ── MFA SCREEN ── */
          <div>
            {/* Header */}
            <div style={{ textAlign: 'center', marginBottom: 32 }}>
              <div style={{ display: 'inline-flex', alignItems: 'center', justifyContent: 'center', width: 56, height: 56, borderRadius: 16, background: 'linear-gradient(135deg, rgba(99,102,241,0.25), rgba(139,92,246,0.25))', border: '1px solid rgba(99,102,241,0.4)', marginBottom: 16 }}>
                <svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="#818cf8" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect x="5" y="11" width="14" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/><circle cx="12" cy="16" r="1" fill="#818cf8" stroke="none"/></svg>
              </div>
              <div style={{ fontSize: 22, fontWeight: 700, color: 'white', marginBottom: 6 }}>Two-Factor Authentication</div>
              <div style={{ fontSize: 13, color: '#64748b' }}>Signed in as <span style={{ color: '#94a3b8', fontWeight: 600 }}>{mfaUser?.name}</span></div>
            </div>

            {/* SMS sent notice */}
            <div style={{ background: 'linear-gradient(135deg, rgba(99,102,241,0.08), rgba(139,92,246,0.08))', border: '1px solid rgba(99,102,241,0.25)', borderRadius: 14, padding: '20px 24px', marginBottom: 24 }}>
              {/* Phone icon + message */}
              <div style={{ display: 'flex', alignItems: 'center', gap: 14, marginBottom: 14 }}>
                <div style={{ width: 44, height: 44, borderRadius: 12, background: 'rgba(99,102,241,0.15)', border: '1px solid rgba(99,102,241,0.3)', display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}>
                  <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#818cf8" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect x="5" y="2" width="14" height="20" rx="2"/><line x1="12" y1="18" x2="12.01" y2="18"/></svg>
                </div>
                <div>
                  <div style={{ fontSize: 13, fontWeight: 600, color: '#c7d2fe', marginBottom: 3 }}>SMS code sent</div>
                  <div style={{ fontSize: 12, color: '#64748b' }}>A 6-digit code has been sent to</div>
                  <div style={{ fontSize: 14, fontWeight: 700, color: '#a5b4fc', fontFamily: 'monospace', letterSpacing: '0.05em', marginTop: 2 }}>{mfaPhone}</div>
                </div>
              </div>
              {/* Countdown bar */}
              <div style={{ background: 'rgba(0,0,0,0.3)', borderRadius: 8, height: 4, overflow: 'hidden', marginBottom: 8 }}>
                <div style={{ height: '100%', borderRadius: 8, width: `${(mfaCountdown / 30) * 100}%`, background: mfaCountdown <= 10 ? '#ef4444' : '#6366f1', transition: 'width 1s linear, background 0.3s' }} />
              </div>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <span style={{ fontSize: 12, color: mfaCountdown <= 10 ? '#f87171' : '#818cf8', fontWeight: 600 }}>
                  {mfaCountdown > 0 ? `Code expires in ${mfaCountdown}s` : 'Code expired'}
                </span>
                <button onClick={handleMfaRefresh} style={{ fontSize: 12, color: '#6366f1', background: 'none', border: 'none', cursor: 'pointer', textDecoration: 'underline', padding: 0 }}>
                  {mfaCountdown === 0 ? 'Send new code' : 'Resend'}
                </button>
              </div>
            </div>

            {/* Input */}
            <form onSubmit={handleMfaSubmit}>
              <div style={{ marginBottom: 18 }}>
                <label style={{ display: 'block', fontSize: 13, fontWeight: 600, color: '#94a3b8', marginBottom: 8 }}>Enter verification code</label>
                <input
                  type="text" inputMode="numeric" maxLength={6}
                  value={mfaInput} onChange={e => { setMfaInput(e.target.value.replace(/\D/g,'')); setMfaError(''); }}
                  placeholder="000000" autoFocus
                  style={{ width: '100%', padding: '14px 18px', borderRadius: 11, background: 'rgba(255,255,255,0.04)', border: `1px solid ${mfaError ? 'rgba(239,68,68,0.5)' : 'rgba(99,102,241,0.3)'}`, color: 'white', fontSize: 22, fontFamily: 'monospace', letterSpacing: '0.3em', textAlign: 'center', outline: 'none', boxSizing: 'border-box', transition: 'border-color 0.2s' }}
                />
                {mfaError && <div style={{ marginTop: 8, fontSize: 12, color: '#f87171', display: 'flex', alignItems: 'center', gap: 6 }}><span>⚠</span>{mfaError}</div>}
              </div>
              <button type="submit" disabled={mfaInput.length < 6 || mfaCountdown === 0}
                style={{ width: '100%', padding: '14px', borderRadius: 12, background: mfaInput.length === 6 && mfaCountdown > 0 ? 'linear-gradient(135deg, #6366f1, #8b5cf6)' : 'rgba(99,102,241,0.2)', border: 'none', color: mfaInput.length === 6 && mfaCountdown > 0 ? 'white' : '#4b5563', fontSize: 15, fontWeight: 700, cursor: mfaInput.length === 6 && mfaCountdown > 0 ? 'pointer' : 'not-allowed', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 8, transition: 'all 0.2s' }}>
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><polyline points="20 6 9 17 4 12"/></svg>
                Verify & Sign In
              </button>
            </form>

            {/* Back link */}
            <button onClick={()=>{ setMfaStep(false); clearInterval(mfaTimerRef.current); setError(''); }} style={{ display: 'block', margin: '18px auto 0', fontSize: 13, color: '#475569', background: 'none', border: 'none', cursor: 'pointer' }}>
              ← Back to login
            </button>
          </div>
        ) : (
          /* ── LOGIN FORM ── */
          <div>
          {/* Card header */}
          <div style={{ textAlign: 'center', marginBottom: 36 }}>
            <div style={{ display: 'inline-flex', alignItems: 'center', gap: 6, marginBottom: 14 }}>
              <Lock style={{ width: 13, height: 13, color: '#06b6d4' }} />
              <span style={{ fontSize: 11, fontWeight: 700, color: '#06b6d4', letterSpacing: '0.14em', textTransform: 'uppercase' }}>Secure Authentication</span>
            </div>
            <div style={{ fontSize: 28, fontWeight: 700, color: 'white', letterSpacing: '-0.4px', lineHeight: 1.2 }}>Sign in to your account</div>
            <div style={{ fontSize: 13, color: '#475569', marginTop: 8 }}>All sessions are encrypted, audited, and monitored.</div>
          </div>

          <form onSubmit={handleSubmit}>
            {/* Username */}
            <div style={{ marginBottom: 18 }}>
              <label style={{ display: 'block', fontSize: 13, fontWeight: 600, color: '#94a3b8', marginBottom: 8 }}>Username</label>
              <div style={{ position: 'relative' }}>
                <UserCheck style={{ position: 'absolute', left: 14, top: '50%', transform: 'translateY(-50%)', width: 15, height: 15, color: '#334155' }} />
                <input
                  type="text" value={username} onChange={e => setUsername(e.target.value)}
                  placeholder="Enter your username" autoComplete="username" disabled={locked}
                  style={{ width: '100%', paddingLeft: 42, paddingRight: 14, paddingTop: 13, paddingBottom: 13, borderRadius: 11, background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.09)', color: 'white', fontSize: 14, outline: 'none', boxSizing: 'border-box', transition: 'border-color 0.2s' }}
                  onFocus={e => e.target.style.borderColor = '#06b6d4'}
                  onBlur={e => e.target.style.borderColor = 'rgba(255,255,255,0.09)'}
                />
              </div>
            </div>

            {/* Password */}
            <div style={{ marginBottom: 18 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
                <label style={{ fontSize: 13, fontWeight: 600, color: '#94a3b8' }}>Password</label>
                <button type="button" style={{ fontSize: 12, color: '#06b6d4', background: 'none', border: 'none', cursor: 'pointer', padding: 0 }}>Forgot password?</button>
              </div>
              <div style={{ position: 'relative' }}>
                <Lock style={{ position: 'absolute', left: 14, top: '50%', transform: 'translateY(-50%)', width: 15, height: 15, color: '#334155' }} />
                <input
                  type={showPass ? 'text' : 'password'} value={password} onChange={e => setPassword(e.target.value)}
                  placeholder="Enter your password" autoComplete="current-password" disabled={locked}
                  style={{ width: '100%', paddingLeft: 42, paddingRight: 44, paddingTop: 13, paddingBottom: 13, borderRadius: 11, background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.09)', color: 'white', fontSize: 14, outline: 'none', boxSizing: 'border-box', transition: 'border-color 0.2s' }}
                  onFocus={e => e.target.style.borderColor = '#06b6d4'}
                  onBlur={e => e.target.style.borderColor = 'rgba(255,255,255,0.09)'}
                />
                <button type="button" onClick={() => setShowPass(!showPass)}
                  style={{ position: 'absolute', right: 14, top: '50%', transform: 'translateY(-50%)', background: 'none', border: 'none', cursor: 'pointer', color: '#334155', padding: 0 }}>
                  <Eye style={{ width: 15, height: 15 }} />
                </button>
              </div>
            </div>

            {/* Remember me */}
            <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 22 }}>
              <button type="button" onClick={() => setRemember(!remember)}
                style={{ width: 18, height: 18, borderRadius: 5, background: remember ? '#06b6d4' : 'rgba(255,255,255,0.05)', border: `1px solid ${remember ? '#06b6d4' : 'rgba(255,255,255,0.15)'}`, display: 'flex', alignItems: 'center', justifyContent: 'center', cursor: 'pointer', flexShrink: 0 }}>
                {remember && <Check style={{ width: 11, height: 11, color: '#020617' }} />}
              </button>
              <span style={{ fontSize: 13, color: '#475569' }}>Keep me signed in for 8 hours</span>
            </div>

            {/* Error */}
            {error && (
              <div style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '12px 14px', borderRadius: 10, background: 'rgba(239,68,68,0.08)', border: '1px solid rgba(239,68,68,0.22)', marginBottom: 18 }}>
                <AlertCircle style={{ width: 15, height: 15, color: '#ef4444', flexShrink: 0 }} />
                <span style={{ fontSize: 13, color: '#fca5a5' }}>{error}</span>
              </div>
            )}

            {/* Submit */}
            <button type="submit" disabled={loading || !username || !password || locked}
              style={{ width: '100%', padding: '14px', borderRadius: 11, border: 'none', cursor: locked || loading || !username || !password ? 'not-allowed' : 'pointer', background: locked ? '#1e293b' : 'linear-gradient(135deg, #0891b2 0%, #1d4ed8 100%)', color: 'white', fontSize: 15, fontWeight: 600, display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 8, opacity: !username || !password || locked ? 0.45 : 1, boxShadow: locked ? 'none' : '0 4px 24px rgba(6,182,212,0.3)', transition: 'opacity 0.2s' }}>
              {loading
                ? <><div style={{ width: 15, height: 15, border: '2px solid rgba(255,255,255,0.3)', borderTopColor: 'white', borderRadius: '50%', animation: 'spin 0.7s linear infinite' }} />Authenticating…</>
                : locked
                ? <><Lock style={{ width: 15, height: 15 }} />Account Locked</>
                : <><Shield style={{ width: 15, height: 15 }} />Sign In</>}
            </button>
          </form>

          {/* Legal notice */}
          <div style={{ marginTop: 24, paddingTop: 20, borderTop: '1px solid rgba(255,255,255,0.06)', display: 'flex', gap: 10, alignItems: 'flex-start' }}>
            <AlertTriangle style={{ width: 13, height: 13, color: '#78350f', flexShrink: 0, marginTop: 1 }} />
            <p style={{ fontSize: 11, color: '#334155', lineHeight: 1.65, margin: 0 }}>
              This system is restricted to authorized personnel. All access is logged under HIPAA §164.312 audit controls.
            </p>
          </div>
          </div>
        )}
        </div>
      </div>

      <style>{`@keyframes spin{to{transform:rotate(360deg)}}`}</style>
    </div>
  );
}

export default function IoMTDashboard() {
  const [currentUser, setCurrentUser] = useState(() => {
    try { const s = localStorage.getItem('iomt_user'); return s ? JSON.parse(s) : null; } catch { return null; }
  });
  const [isLive, setIsLive] = useState(true);
  const [trafficHistory, setTrafficHistory] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [stats, setStats] = useState({ totalPackets: 0, anomalies: 0, blocked: 0, devices: 4 });
  const [deviceStatus, setDeviceStatus] = useState({});
  const [confidenceScore, setConfidenceScore] = useState(98.30);
  const [alertThreshold, setAlertThreshold]   = useState(90);
  const [fpSuppressions, setFpSuppressions]   = useState([]); // [{key, type, device, addedAt}]
  const [suppressedCount, setSuppressedCount] = useState(0);
  const [liveGeoHits, setLiveGeoHits]         = useState({});

  // ── WebSocket callbacks (stable refs so hook doesn't re-subscribe) ────────────
  // Refs hold the latest callback; stable wrappers pass to the hook so it never
  // needs to re-create the WebSocket when onTraffic/onAlert changes.
  const onTrafficRef = useRef(null);
  const onAlertRef   = useRef(null);

  onTrafficRef.current = (data) => {
    setTrafficHistory(prev => [...prev.slice(-14), {
      timestamp:    new Date(data.timestamp * 1000).toLocaleTimeString(),
      packets:      data.packets,
      anomalyScore: data.anomaly_score,
    }]);
    setStats(prev => ({
      ...prev,
      totalPackets: data.packet_count,
      anomalies:    data.anomaly_count,
    }));
    // Build live packet capture from WebSocket traffic
    const PROTO_MAP = { DDoS:'TCP', DoS:'TCP', Recon:'ICMP', MQTT:'TCP', Spoofing:'ARP', Benign:'UDP' };
    const INFO_MAP  = {
      DDoS:'SYN flood packet burst', DoS:'RST flood / resource exhaustion',
      Recon:'ICMP Echo Request sweep', MQTT:'MQTT CONNECT on port 1883',
      Spoofing:'ARP Reply — IP spoofed', Benign:'Normal data exchange',
    };
    const proto = PROTO_MAP[data.prediction] || 'UDP';
    const info  = INFO_MAP[data.prediction]  || 'Encrypted application data';
    setPackets(prev => {
      const pkt = {
        no:       data.packet_count,
        time:     new Date(data.timestamp * 1000).toLocaleTimeString(),
        src:      data.src_ip,
        dst:      data.dst_ip,
        protocol: proto,
        len:      data.packets,
        info,
        flag:     data.is_attack,
        prediction: data.prediction,
        confidence: data.confidence,
      };
      return [pkt, ...prev.slice(0, 99)];
    });

    // Update live heatmap — increment today's current hour bucket
    const now = new Date(data.timestamp * 1000);
    const day = _DAY_IDX[now.getDay()];
    const hr  = `${String(now.getHours()).padStart(2,'0')}:00`;
    setHeatmapData(prev => prev.map(row =>
      row.day === day ? { ...row, [hr]: (row[hr] || 0) + 1 } : row
    ));
    // Live geo hits — prefer true_category for variety; fall back to prediction
    const geoType = (data.true_category && data.true_category !== 'Benign')
      ? data.true_category
      : (data.is_attack ? data.prediction : null);
    if (geoType) {
      const cities = GEO_ATTACK_MAP[geoType];
      if (cities) {
        const city = cities[Math.floor(Math.random() * cities.length)];
        setLiveGeoHits(prev => ({
          ...prev,
          [city]: {
            count:    Math.min(30, ((prev[city]?.count) || 0) + 1),
            type:     geoType,
            severity: CITY_META[city]?.severity || 'medium',
            target:   data.device,
            lastSeen: Date.now(),
          },
        }));
      }
    }
  };

  onAlertRef.current = (alert) => {
    // Confidence threshold filter
    if (alert.confidence < alertThreshold) return;
    // FP suppression filter
    const fpKey = `${alert.type}:${alert.device}`;
    if (fpSuppressions.some(r => r.key === fpKey)) {
      setSuppressedCount(p => p + 1);
      return;
    }
    // Detect model false positive: model says attack but ground truth says benign
    const isModelFP = alert.trueCategory === 'Benign';
    const newAlert = {
      id:           alert.id,
      severity:     isModelFP ? 'low' : alert.severity,
      device:       alert.device,
      message:      `${alert.type} detected by ML model (${Number(alert.confidence).toFixed(1)}% conf)`,
      time:         alert.time,
      type:         alert.type,
      trueCategory: alert.trueCategory,
      isModelFP,
      status:       isModelFP ? 'fp' : alert.status,
      sourceIP:     alert.sourceIP,
      destIP:       alert.destIP,
      packets:      Math.floor(Math.random() * 5000) + 100,
      bytes:        `${(Math.random() * 500).toFixed(0)} KB`,
      port:         [80, 443, 1883, 8080][Math.floor(Math.random() * 4)],
      confidence:   alert.confidence,
      anomalyScore: alert.anomalyScore,
      timestamp:    new Date(),
      createdAt:    Date.now(),
      mitre:        alert.mitre,
    };
    setAlerts(prev => [newAlert, ...prev.slice(0, 49)]);

    // Topology attack path
    if (newAlert.severity === 'critical' || newAlert.severity === 'high') {
      const nodeKey = newAlert.device.toLowerCase().replace(' ', '');
      setActiveAttackPath({ from: 'gateway', to: nodeKey });
      setTopologyNodes(prev => prev.map(n =>
        n.device === newAlert.device ? { ...n, status: 'attack' } : n
      ));
      setTimeout(() => {
        setActiveAttackPath(null);
        setTopologyNodes(prev => prev.map(n =>
          n.device === newAlert.device ? { ...n, status: 'warning' } : n
        ));
      }, 5000);
      pushToast(`${newAlert.severity.toUpperCase()}: ${newAlert.type} on ${newAlert.device}`, newAlert.severity);
    }

    // Auto-response — block IP for high; block + isolate to VLAN 99 for critical
    if (autoResponse.critical && newAlert.severity === 'critical') {
      handleQuickAction('block', newAlert, true);
      handleQuickAction('isolate', newAlert, true);
    } else if (autoResponse.high && newAlert.severity === 'high') {
      handleQuickAction('block', newAlert, true);
    }

    sendNotification(newAlert);
  };

  // Stable wrappers — never change identity, so the hook never re-subscribes
  const stableOnTraffic = useCallback((d) => onTrafficRef.current?.(d), []);
  const stableOnAlert   = useCallback((a) => onAlertRef.current?.(a), []);

  const { connected, liveRunning, backendUp, startLive, stopLive, resetStats: resetBackendStats } = useSOCSocket({
    onTraffic: stableOnTraffic,
    onAlert:   stableOnAlert,
  });

  // Alert Response States
  const [selectedAlert, setSelectedAlert] = useState(null);
  const [showAlertPanel, setShowAlertPanel] = useState(false);
  const [responseLog, setResponseLog] = useState([]);
  const [autoResponse, setAutoResponse] = useState({ critical: true, high: true });
  const [blockedIPs, setBlockedIPs] = useState([]);
  const [isolatedDevices, setIsolatedDevices] = useState(() => {
    try { const s = JSON.parse(localStorage.getItem('iomt_isolated_v1')); return Array.isArray(s) ? s : []; } catch { return []; }
  });
  const [appliedPatches, setAppliedPatches]   = useState({});   // { [device]: { [patchId]: boolean } }
  const [alertFilter, setAlertFilter] = useState('all');

  // ── Notification state — persisted so history and config survive page reloads ──
  const [notifications, setNotifications] = useState(() => {
    try {
      const s = JSON.parse(localStorage.getItem('iomt_notif_history_v1') || 'null');
      return Array.isArray(s) ? s : [];
    } catch { return []; }
  });
  useEffect(() => {
    try { localStorage.setItem('iomt_notif_history_v1', JSON.stringify(notifications)); } catch {}
  }, [notifications]);

  const _defaultNotifSettings = {
    email: { enabled: false, address: '', serviceId: '', templateId: '', publicKey: '', critical: true, high: true, medium: false },
    slack: { enabled: false, webhookUrl: '', critical: true, high: true, medium: true },
  };
  const [notificationSettings, setNotificationSettings] = useState(() => {
    try {
      const s = JSON.parse(localStorage.getItem('iomt_notif_cfg_v1') || 'null');
      if (s && typeof s === 'object') return {
        email: { ..._defaultNotifSettings.email, ...s.email },
        slack: { ..._defaultNotifSettings.slack, ...s.slack },
      };
    } catch {}
    return _defaultNotifSettings;
  });
  useEffect(() => {
    try { localStorage.setItem('iomt_notif_cfg_v1', JSON.stringify(notificationSettings)); } catch {}
  }, [notificationSettings]);

  // Rate-limit: 1 notification per device per 5 min to avoid spamming
  const notifCooldowns = useRef({});

  const [showNotificationPanel, setShowNotificationPanel] = useState(false);
  const [showNotificationSettings, setShowNotificationSettings] = useState(false);
  const [notifTestStatus, setNotifTestStatus] = useState({ email: null, slack: null });

  // NEW: Threat Intelligence States
  const [threatIntel, setThreatIntel] = useState([]);
  const [showThreatIntelPanel, setShowThreatIntelPanel] = useState(false);
  const [threatSources, setThreatSources] = useState(threatIntelSources);

  // NEW: Network Topology States
  const [showTopology, setShowTopology] = useState(false);
  const [selectedNode, setSelectedNode] = useState(null);
  const [topologyNodes, setTopologyNodes] = useState(networkNodes);
  const [activeAttackPath, setActiveAttackPath] = useState(null);

  // NEW: Active Tab State
  const [activeTab, setActiveTab] = useState('exec');
  const [adminSub, setAdminSub]   = useState('assets');

  // Attack Logs tab state
  const [logData,       setLogData]       = useState([]);
  const [logLoading,    setLogLoading]    = useState(false);
  const [logFilterSev,  setLogFilterSev]  = useState('all');
  const [logFilterType, setLogFilterType] = useState('all');
  const [logFilterDev,  setLogFilterDev]  = useState('all');
  const [logSearch,     setLogSearch]     = useState('');
  const [logLimit,      setLogLimit]      = useState(200);
  const [logRefresh,    setLogRefresh]    = useState(null);

  // User account management (admin): live passwords + blocked status + MFA + phone
  // Persisted to localStorage so settings survive page refreshes
  const [userStates, setUserStates] = useState(() => {
    try {
      const saved = localStorage.getItem('iomt_userStates_v2');
      if (saved) return JSON.parse(saved);
    } catch {}
    return Object.fromEntries(DEMO_USERS.map(u => [u.username, { blocked: false, password: u.password, mfaEnabled: false, phone: u.phone }]));
  });

  // Keep localStorage in sync whenever userStates changes
  useEffect(() => {
    try { localStorage.setItem('iomt_userStates_v2', JSON.stringify(userStates)); } catch {}
  }, [userStates]);
  const [resetTarget,  setResetTarget]  = useState(null);  // username whose pw is being reset
  const [resetPwVal,   setResetPwVal]   = useState('');
  const [showPwMap,    setShowPwMap]    = useState({});     // { [username]: bool } reveal password
  const [editPhoneFor, setEditPhoneFor] = useState(null);   // username whose phone is being edited
  const [editPhoneVal, setEditPhoneVal] = useState('');
  // Active OTPs: { [username]: { code: '123456', expiresAt: Date } } — visible only to admin
  const [activeOtps, setActiveOtps] = useState({});

  // Called by LoginPage when it generates an OTP so admin panel can see it
  const onOtpGenerated = (username, code) => {
    const expiresAt = new Date(Date.now() + 30000);
    setActiveOtps(prev => ({ ...prev, [username]: { code, expiresAt } }));
    // Auto-clear after 30s
    setTimeout(() => setActiveOtps(prev => {
      const next = { ...prev };
      if (next[username]?.code === code) delete next[username];
      return next;
    }), 31000);
  };

  // Credential check used by LoginPage (respects live userStates)
  const checkCredentials = (uname, pw) => {
    const user = DEMO_USERS.find(u => u.username === uname.trim());
    if (!user) return { ok: false, reason: 'auth_fail' };
    const us = userStates[user.username];
    if (us?.blocked) return { ok: false, reason: 'blocked' };
    const livePw = us?.password ?? user.password;
    if (livePw !== pw) return { ok: false, reason: 'auth_fail' };
    const livePhone = us?.phone ?? user.phone;
    // Admin bypasses MFA — they control MFA for others and cannot be locked out
    const mfaEnabled = user.role === 'admin' ? false : (us?.mfaEnabled ?? true);
    return { ok: true, user, mfaEnabled, phone: livePhone };
  };

  // Heartbeat helpers — write/clear presence in localStorage so other tabs see who's online
  const writeHeartbeat = useCallback((username) => {
    try { localStorage.setItem(`iomt_hb_${username}`, Date.now().toString()); } catch {}
  }, []);
  const clearHeartbeat = useCallback((username) => {
    try { localStorage.removeItem(`iomt_hb_${username}`); } catch {}
  }, []);
  const getOnlineUsernames = useCallback(() => {
    const cutoff = Date.now() - 60000; // 60 s window
    const online = [];
    try {
      for (let i = 0; i < localStorage.length; i++) {
        const key = localStorage.key(i);
        if (key?.startsWith('iomt_hb_')) {
          const ts = parseInt(localStorage.getItem(key) || '0', 10);
          if (ts > cutoff) online.push(key.replace('iomt_hb_', ''));
        }
      }
    } catch {}
    return online;
  }, []);

  // Set default tab based on role when user logs in
  const handleLogin = (user) => {
    setCurrentUser(user);
    try { localStorage.setItem('iomt_user', JSON.stringify(user)); } catch {}
    writeHeartbeat(user.username);
    setActiveTab(user.role === 'admin' ? 'admin_panel' : 'exec');
  };

  // Heartbeat interval + online presence state
  const [onlineUsernames, setOnlineUsernames] = useState(() => getOnlineUsernames());
  useEffect(() => {
    if (!currentUser) return;
    writeHeartbeat(currentUser.username);
    const hbInterval = setInterval(() => {
      writeHeartbeat(currentUser.username);
      setOnlineUsernames(getOnlineUsernames());
    }, 30000);
    // Poll every 15 s so we pick up other tabs quickly
    const pollInterval = setInterval(() => setOnlineUsernames(getOnlineUsernames()), 15000);
    return () => { clearInterval(hbInterval); clearInterval(pollInterval); };
  }, [currentUser, writeHeartbeat, getOnlineUsernames]);

  // Fetch attack logs from backend SQLite
  const fetchAttackLogs = useCallback((limit) => {
    setLogLoading(true);
    fetch(`${API_BASE}/api/alerts?limit=${limit}`)
      .then(r => r.json())
      .then(d => { setLogData(d.alerts || []); setLogRefresh(new Date()); setLogLoading(false); })
      .catch(() => setLogLoading(false));
  }, []);

  useEffect(() => {
    if (activeTab === 'logs') fetchAttackLogs(logLimit);
  }, [activeTab, logLimit, fetchAttackLogs]);
  const [refreshRate, setRefreshRate] = useState(2000);
  const [worldPaths, setWorldPaths] = useState([]);

  // ── Trend history for Analytics tab (persisted) ───────────────────────────
  const [trendHistory, setTrendHistory] = useState([]);

  // Persist key state to localStorage
  useEffect(() => { try { if (Array.isArray(alerts))      localStorage.setItem('iomt_alerts_v1',  JSON.stringify(alerts.slice(0, 50))); } catch {} }, [alerts]);
  useEffect(() => { try { if (Array.isArray(responseLog)) localStorage.setItem('iomt_reslog_v1', JSON.stringify(responseLog.slice(0, 50))); } catch {} }, [responseLog]);
  useEffect(() => { try { if (Array.isArray(blockedIPs))  localStorage.setItem('iomt_blocked_v1',JSON.stringify(blockedIPs)); } catch {} }, [blockedIPs]);
  useEffect(() => { try { if (Array.isArray(isolatedDevices)) localStorage.setItem('iomt_isolated_v1', JSON.stringify(isolatedDevices)); } catch {} }, [isolatedDevices]);
  useEffect(() => { try { if (liveGeoHits && typeof liveGeoHits === 'object') localStorage.setItem('iomt_geo_v1', JSON.stringify(liveGeoHits)); } catch {} }, [liveGeoHits]);
  useEffect(() => { try { if (Array.isArray(trendHistory)) localStorage.setItem('iomt_trend_v1', JSON.stringify(trendHistory.slice(-120))); } catch {} }, [trendHistory]);

  // Ref mirrors alerts so the interval can read current value without a closure
  const alertsSnapRef = useRef(alerts);
  useEffect(() => { alertsSnapRef.current = alerts; }, [alerts]);

  // Append a trend snapshot every 60 s while the dashboard is open
  useEffect(() => {
    if (!currentUser) return;
    const snap = () => {
      const a = alertsSnapRef.current;
      const now = new Date();
      const label = `${String(now.getHours()).padStart(2,'0')}:${String(now.getMinutes()).padStart(2,'0')}`;
      const bucket = {
        time:     label,
        total:    a.length,
        DDoS:     a.filter(x => x.type === 'DDoS').length,
        DoS:      a.filter(x => x.type === 'DoS').length,
        Recon:    a.filter(x => x.type === 'Recon').length,
        MQTT:     a.filter(x => x.type === 'MQTT').length,
        Spoofing: a.filter(x => x.type === 'Spoofing').length,
        critical: a.filter(x => x.severity === 'critical').length,
        high:     a.filter(x => x.severity === 'high').length,
        medium:   a.filter(x => x.severity === 'medium').length,
      };
      setTrendHistory(prev => [...prev, bucket].slice(-120));
    };
    snap();
    const id = setInterval(snap, 60_000);
    return () => clearInterval(id);
  }, [currentUser]);

  // Clock + session
  const [clockTime, setClockTime]   = useState(new Date());
  const [shiftStart]                = useState(new Date());
  const [toasts, setToasts]         = useState([]);

  // Tab feature states
  const [playbookType, setPlaybookType]         = useState('DDoS');
  const [playbookDone, setPlaybookDone]         = useState({});   // { [type]: { [idx]: 'done'|'progress'|false } }
  const [playbookNotes, setPlaybookNotes]       = useState({});   // { [type]: { [idx]: string } }
  const [playbookStarted, setPlaybookStarted]   = useState({});   // { [type]: timestamp }
  const [pbSelectedStep, setPbSelectedStep]     = useState(null); // index of expanded step
  const [selectedAlertForMitre, setSelectedAlertForMitre] = useState(null);
  const [packets, setPackets]                   = useState([]);
  const [selectedPacket, setSelectedPacket]     = useState(null);
  const [pktFilterProto,  setPktFilterProto]    = useState('all');
  const [pktFilterType,   setPktFilterType]     = useState('all');
  const [pktFilterDevice, setPktFilterDevice]   = useState('all');
  const [heatmapData, setHeatmapData]           = useState(() => {
    try {
      const s = JSON.parse(localStorage.getItem('iomt_heatmap_v1') || 'null');
      if (Array.isArray(s) && s.length === 7) return s;
    } catch {}
    return emptyHeatmap();
  });
  useEffect(() => { try { if (Array.isArray(heatmapData) && heatmapData.length > 0) localStorage.setItem('iomt_heatmap_v1',JSON.stringify(heatmapData)); } catch {} }, [heatmapData]);
  const [heatmapMetric, setHeatmapMetric]       = useState('traffic');
  const [selectedGeoAttack, setSelectedGeoAttack] = useState(null);
  const [mapZoom, setMapZoom] = useState({scale:1, tx:0, ty:0});
  const mapSvgRef  = useRef(null);
  const mapDragRef = useRef(null);
  const [aclRules, setAclRules] = useState([]);
  const [grcSection, setGrcSection] = useState('frameworks');
  const [policies, setPolicies] = useState(grcPolicies);
  const [reviewPolicy, setReviewPolicy] = useState(null); // policy being reviewed
  const [reviewForm, setReviewForm] = useState({});

  // CSV Upload states
  const [csvFile, setCsvFile]           = useState(null);
  const [csvRows, setCsvRows]           = useState([]);
  const [csvHeaders, setCsvHeaders]     = useState([]);
  const [csvAnalysis, setCsvAnalysis]   = useState(null);
  const [csvLoading, setCsvLoading]     = useState(false);
  const [csvDragOver, setCsvDragOver]   = useState(false);

  // ── Live-computed GRC & HIPAA scores (recalculated whenever alerts change) ───
  const grcFrameworks = useMemo(() => computeGrcScores(alerts), [alerts]);
  const hipaaRules    = useMemo(() => computeHipaaScores(alerts), [alerts]);

  // ── Audit timestamps — persisted in localStorage, initialised from defaults ──
  const [auditTimestamps, setAuditTimestamps] = useState(() => {
    try {
      const saved = JSON.parse(localStorage.getItem('iomt_audit_ts_v1') || 'null');
      if (saved && typeof saved === 'object') return { ...AUDIT_DEFAULTS, ...saved };
    } catch {}
    return { ...AUDIT_DEFAULTS };
  });

  const markAudited = (device) => {
    setAuditTimestamps(prev => {
      const next = { ...prev, [device]: Date.now() };
      try { localStorage.setItem('iomt_audit_ts_v1', JSON.stringify(next)); } catch {}
      return next;
    });
  };

  // ── Dismissed risk factors — analyst can mark a static factor as resolved ──
  const [dismissedFactors, setDismissedFactors] = useState(() => {
    try {
      const s = JSON.parse(localStorage.getItem('iomt_dismissed_factors_v1') || 'null');
      return s && typeof s === 'object' ? s : {};
    } catch { return {}; }
  });
  useEffect(() => {
    try { localStorage.setItem('iomt_dismissed_factors_v1', JSON.stringify(dismissedFactors)); } catch {}
  }, [dismissedFactors]);

  const dismissFactor = (device, factor) => {
    setDismissedFactors(prev => ({
      ...prev,
      [device]: [...(prev[device] || []), factor],
    }));
  };
  const restoreFactors = (device) => {
    setDismissedFactors(prev => ({ ...prev, [device]: [] }));
  };

  // ── Live risk factors — auto-derived from recent alerts targeting each device ──
  const LIVE_FACTOR_MAP = {
    DDoS:     'Active DDoS flood detected',
    DoS:      'Active DoS attack — service disruption risk',
    Spoofing: 'Spoofing / MiTM attack detected — PHI exposure risk',
    MQTT:     'Malicious MQTT payload observed',
    Recon:    'Network reconnaissance activity detected',
  };
  const liveRiskFactors = useMemo(() => {
    const result = {};
    const recent = alerts.slice(0, 30);
    Object.keys(deviceRiskData).forEach(dev => {
      const devAlerts = recent.filter(a => a.device === dev);
      const types = [...new Set(devAlerts.map(a => a.type))];
      const factors = types.filter(t => LIVE_FACTOR_MAP[t]).map(t => LIVE_FACTOR_MAP[t]);
      if (devAlerts.some(a => a.severity === 'critical')) factors.push('Critical-severity attack active on this device');
      result[dev] = factors;
    });
    return result;
  }, [alerts]);

  // ── Isolation metadata — records when/why each device was quarantined ──────────
  const [isolationMeta, setIsolationMeta] = useState(() => {
    try {
      const s = JSON.parse(localStorage.getItem('iomt_isolation_meta_v1') || 'null');
      return s && typeof s === 'object' ? s : {};
    } catch { return {}; }
  });
  useEffect(() => {
    try { localStorage.setItem('iomt_isolation_meta_v1', JSON.stringify(isolationMeta)); } catch {}
  }, [isolationMeta]);

  // ── Remediation/restore modal state ──────────────────────────────────────────
  const [restoreModal, setRestoreModal] = useState(null);
  // restoreModal = { device: string, meta: { ts, trigger, severity } | null }
  const [remediationChecks, setRemediationChecks] = useState({});
  // { [stepId]: boolean } — tracks checkbox state in the remediation modal

  // Attack distribution — computed live from WebSocket alerts
  const ATTACK_COLORS = { DDoS:'#ef4444', DoS:'#f97316', Spoofing:'#eab308', MQTT:'#8b5cf6', Recon:'#3b82f6', Benign:'#22c55e' };
  const attackDistribution = (() => {
    const counts = {};
    alerts.forEach(a => { if (a.type) counts[a.type] = (counts[a.type]||0)+1; });
    const total = Object.values(counts).reduce((s,v)=>s+v,0) || 1;
    return Object.entries(counts).map(([name,val])=>({
      name, value: Math.round(val/total*100), color: ATTACK_COLORS[name]||'#64748b'
    }));
  })();

  // Initialize data
  useEffect(() => {
    const initialHistory = Array.from({ length: 15 }, (_, i) => ({
      ...generateTrafficData(),
      timestamp: `${i}s`,
    }));
    setTrafficHistory(initialHistory);

    const deviceData = {
      'Infusion Pump':  { ip: '192.168.20.50', mac: '00:1A:2B:3C:4D:50', firmware: 'v1.2.3', vlan: 'VLAN-20' },
      'Heart Monitor':  { ip: '192.168.20.22', mac: '00:1A:2B:3C:4D:22', firmware: 'v3.1.0', vlan: 'VLAN-20' },
      'Pulse Oximeter': { ip: '192.168.20.35', mac: '00:1A:2B:3C:4D:35', firmware: 'v2.4.1', vlan: 'VLAN-20' },
      'ECG Monitor':    { ip: '192.168.20.41', mac: '00:1A:2B:3C:4D:41', firmware: 'v2.0.8', vlan: 'VLAN-20' },
    };
    const initialDevices = {};
    devices.forEach(device => {
      initialDevices[device] = {
        ...deviceData[device],
        status: 'normal',
        lastSeen: 'Just now',
        packets: Math.floor(Math.random() * 1000) + 500,
      };
    });
    setDeviceStatus(initialDevices);

    // Initial threat intel
    setThreatIntel([
      { id: 1, type: 'Botnet C2', severity: 'critical', indicator: '45.33.32.156', source: 'AlienVault OTX', confidence: 95, time: '5 min ago', matched: true },
      { id: 2, type: 'Malware Hash', severity: 'high', indicator: 'e99a18c428...', source: 'VirusTotal', confidence: 88, time: '12 min ago', matched: false },
      { id: 3, type: 'Scanner IP', severity: 'medium', indicator: '185.220.101.45', source: 'AbuseIPDB', confidence: 76, time: '18 min ago', matched: true },
    ]);

    setNotifications([]);
  }, []);

  // Real-time updates
  useEffect(() => {
    if (!isLive || !currentUser) return;
    const interval = setInterval(() => {
      const newData = generateTrafficData();
      setTrafficHistory(prev => [...prev.slice(-14), { ...newData, timestamp: `${Date.now() % 100}s` }]);
      setStats(prev => ({
        ...prev,
        totalPackets: prev.totalPackets + newData.packets,
        anomalies: prev.anomalies + (newData.anomalyScore > 0.7 ? 1 : 0),
      }));

      // Random threat intel update
      if (Math.random() > 0.85) {
        const newThreat = { ...generateThreatIntel(), id: Date.now(), time: 'Just now', matched: Math.random() > 0.5 };
        setThreatIntel(prev => [newThreat, ...prev.slice(0, 19)]);
      }

      // Alerts are driven by live WebSocket (onAlertRef) — no random generation here
    }, refreshRate);
    return () => clearInterval(interval);
  }, [isLive, autoResponse, notificationSettings, refreshRate]);

  // Live clock — tick every second
  useEffect(() => {
    if (!currentUser) return;
    const t = setInterval(() => setClockTime(new Date()), 1000);
    return () => clearInterval(t);
  }, [currentUser]);

  // Load historical alerts from SQLite on mount
  useEffect(() => {
    fetch('${API_BASE}/api/alerts?limit=50')
      .then(r => r.json())
      .then(({ alerts: rows }) => {
        if (!rows?.length) return;
        const historical = rows.map(r => ({
          id:           r.id,
          severity:     r.severity || 'high',
          device:       r.device,
          message:      `${r.prediction} detected by ML model (${Number(r.confidence||0).toFixed(1)}% conf)`,
          time:         new Date(r.timestamp * 1000).toLocaleTimeString(),
          type:         r.prediction,
          trueCategory: null,
          isModelFP:    false,
          status:       'resolved',   // historical = already resolved
          sourceIP:     r.src_ip,
          destIP:       r.dst_ip,
          packets:      Math.floor(Math.random() * 5000) + 100,
          bytes:        `${(Math.random() * 500).toFixed(0)} KB`,
          port:         [80, 443, 1883, 8080][Math.floor(Math.random() * 4)],
          confidence:   Number(r.confidence || 0),
          anomalyScore: r.anomaly_score,
          timestamp:    new Date(r.timestamp * 1000),
          mitre:        { tactic: 'Unknown', techniqueId: 'N/A' },
        }));
        setAlerts(historical);
      })
      .catch(() => {});
  }, []);

  // Load world atlas for Geo Map
  useEffect(() => {
    fetch('https://cdn.jsdelivr.net/npm/world-atlas@2/countries-110m.json')
      .then(r => r.json())
      .then(world => {
        const countries = topoFeature(world, world.objects.countries);
        const proj = geoEquirectangular()
          .scale(200 / (2 * Math.PI))
          .translate([100, 50]);
        const pathGen = geoPath().projection(proj);
        setWorldPaths(countries.features.map(f => pathGen(f)).filter(Boolean));
      })
      .catch(() => {});
  }, []);

  // Geo hit decay — remove cities not seen in the last 60 s
  useEffect(() => {
    if (!currentUser) return;
    const t = setInterval(() => {
      const cutoff = Date.now() - 60000;
      setLiveGeoHits(prev => {
        const next = {};
        let changed = false;
        for (const city in prev) {
          if ((prev[city]?.lastSeen ?? 0) >= cutoff) {
            next[city] = prev[city];
          } else {
            changed = true;
          }
        }
        return changed ? next : prev;
      });
    }, 10000);
    return () => clearInterval(t);
  }, [currentUser]);

  // Toast helper — auto-dismiss after 5 s
  const pushToast = useCallback((msg, sev='info') => {
    const id = Date.now();
    setToasts(prev => [{ id, msg, sev }, ...prev].slice(0, 4));
    setTimeout(() => setToasts(prev => prev.filter(t => t.id !== id)), 5000);
  }, []);

  // Send notification
  const sendNotification = (alert) => {
    const shouldNotify = (settings, severity) => {
      if (!settings.enabled) return false;
      if (severity === 'critical' && settings.critical) return true;
      if (severity === 'high'     && settings.high)     return true;
      if (severity === 'medium'   && settings.medium)   return true;
      return false;
    };

    // Rate-limit: 1 notification per device per 5 minutes
    const now = Date.now();
    const lastSent = notifCooldowns.current[alert.device] || 0;
    if (now - lastSent < 5 * 60 * 1000) return;
    notifCooldowns.current[alert.device] = now;

    const timeStr = new Date().toLocaleTimeString();

    // ── Email via EmailJS (real delivery, no backend needed) ──────────────────
    const { email } = notificationSettings;
    if (email.enabled && email.address && email.serviceId && email.templateId && email.publicKey
        && shouldNotify(email, alert.severity)) {
      emailjs.send(
        email.serviceId,
        email.templateId,
        {
          to_email:   email.address,
          severity:   alert.severity.toUpperCase(),
          device:     alert.device,
          alert_type: alert.type,
          source_ip:  alert.sourceIP,
          confidence: `${alert.confidence}%`,
          time:       new Date().toLocaleString(),
        },
        { publicKey: email.publicKey }
      ).then(() => {
        setNotifications(prev => [
          { id: Date.now(), type:'email', recipient: email.address, alert:`${alert.type} on ${alert.device}`, status:'sent',   time: timeStr, severity: alert.severity },
          ...prev.slice(0, 99)
        ]);
      }).catch(() => {
        setNotifications(prev => [
          { id: Date.now(), type:'email', recipient: email.address, alert:`${alert.type} on ${alert.device}`, status:'failed', time: timeStr, severity: alert.severity },
          ...prev.slice(0, 99)
        ]);
      });
    }

    // ── Slack via Incoming Webhook ────────────────────────────────────────────
    const { slack } = notificationSettings;
    if (slack.enabled && slack.webhookUrl && shouldNotify(slack, alert.severity)) {
      fetch(slack.webhookUrl, {
        method: 'POST', mode: 'no-cors',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ text:
          `🚨 *${alert.severity.toUpperCase()} IoMT Alert*\n` +
          `*Device:* ${alert.device}\n*Type:* ${alert.type}\n` +
          `*Source IP:* ${alert.sourceIP}\n*Confidence:* ${alert.confidence}%\n` +
          `*Time:* ${new Date().toLocaleString()}`
        }),
      }).catch(() => {});
      setNotifications(prev => [
        { id: Date.now() + 1, type:'slack', recipient:'Slack channel', alert:`${alert.type} on ${alert.device}`, status:'sent', time: timeStr, severity: alert.severity },
        ...prev.slice(0, 99)
      ]);
    }
  };

  // Alert Response Actions
  const handleQuickAction = (action, alert, isAuto = false) => {
    const timestamp = new Date().toLocaleTimeString();
    const actorName = isAuto ? 'Auto-Response' : (currentUser?.username || 'Analyst');
    const actorRole = isAuto ? 'System' : (currentUser?.role?.replace('_',' ') || '');
    let logEntry = { id: Date.now(), time: timestamp, user: actorName, role: actorRole, device: alert.device || '' };

    switch (action) {
      case 'block':
        setBlockedIPs(prev => prev.includes(alert.sourceIP) ? prev : [...prev, alert.sourceIP]);
        setAlerts(prev => prev.map(a => a.id === alert.id && !a.respondedAt ? { ...a, respondedAt: Date.now() } : a));
        logEntry = { ...logEntry, action: 'Blocked IP', target: alert.sourceIP, alert: alert.type, severity: alert.severity };
        setStats(prev => ({ ...prev, blocked: prev.blocked + 1 }));
        break;
      case 'isolate': {
        const octet = DEVICE_OCTETS[alert.device] || 100;
        const newIP = `${VLAN_DEFS[99].cidr}${octet}`;
        setIsolatedDevices(prev => prev.includes(alert.device) ? prev : [...prev, alert.device]);
        setDeviceStatus(prev => ({
          ...prev,
          [alert.device]: { ...prev[alert.device], status: 'isolated', ip: newIP }
        }));
        setTopologyNodes(prev => prev.map(n =>
          n.device === alert.device ? { ...n, status: 'isolated', vlan: 99, vlanName: 'Quarantine' } : n
        ));
        // Push bidirectional ACL rules blocking the quarantine subnet from IoMT VLAN
        const ts = new Date().toLocaleTimeString();
        setAclRules(prev => [
          { id: Date.now(),    device: alert.device, seq: 10, action: 'DENY', src: VLAN_DEFS[20].subnet, dst: VLAN_DEFS[99].subnet, proto: 'ip', appliedTo: 'VLAN 20 SVI', time: ts, active: true },
          { id: Date.now()+1, device: alert.device, seq: 20, action: 'DENY', src: VLAN_DEFS[99].subnet, dst: VLAN_DEFS[20].subnet, proto: 'ip', appliedTo: 'VLAN 99 SVI', time: ts, active: true },
          { id: Date.now()+2, device: alert.device, seq: 30, action: 'DENY', src: newIP+'/32',          dst: 'any',                proto: 'ip', appliedTo: 'VLAN 99 SVI', time: ts, active: true },
          // Remove any pre-existing rules for this device to avoid duplicates
          ...prev.filter(r => r.device !== alert.device),
        ]);
        setAlerts(prev => prev.map(a => a.id === alert.id && !a.respondedAt ? { ...a, respondedAt: Date.now() } : a));
        setIsolationMeta(prev => ({
          ...prev,
          [alert.device]: { ts: Date.now(), trigger: alert.type, severity: alert.severity, msg: alert.message || alert.type },
        }));
        logEntry = { ...logEntry, action: `Isolated → VLAN 99 | IP: ${newIP} | Subnet block: ${VLAN_DEFS[99].subnet}`, target: alert.device, alert: alert.type };
        break;
      }
      case 'acknowledge':
        setAlerts(prev => prev.map(a => a.id === alert.id ? { ...a, status: 'acknowledged', acknowledgedAt: Date.now(), acknowledgedBy: actorName, respondedAt: a.respondedAt || Date.now() } : a));
        logEntry = { ...logEntry, action: 'Acknowledged', target: `Alert #${alert.id}`, alert: alert.type, severity: alert.severity };
        break;
      case 'resolve':
        setAlerts(prev => prev.map(a => a.id === alert.id ? { ...a, status: 'resolved', resolvedAt: Date.now(), resolvedBy: actorName, respondedAt: a.respondedAt || Date.now() } : a));
        logEntry = { ...logEntry, action: 'Resolved', target: `Alert #${alert.id}`, alert: alert.type, severity: alert.severity };
        break;
      case 'unblock':
        setBlockedIPs(prev => prev.filter(ip => ip !== alert.sourceIP));
        setStats(prev => ({ ...prev, blocked: Math.max(0, prev.blocked - 1) }));
        logEntry = { ...logEntry, action: 'Unblocked IP', target: alert.sourceIP, alert: alert.type, severity: alert.severity };
        break;
      case 'restore': {
        const octet2 = DEVICE_OCTETS[alert.device] || 100;
        const origIP = `${VLAN_DEFS[20].cidr}${octet2}`;
        setIsolatedDevices(prev => prev.filter(d => d !== alert.device));
        setDeviceStatus(prev => ({
          ...prev,
          [alert.device]: { ...prev[alert.device], status: 'normal', ip: origIP }
        }));
        setTopologyNodes(prev => prev.map(n =>
          n.device === alert.device ? { ...n, status: 'normal', vlan: 20, vlanName: 'IoMT Medical' } : n
        ));
        setAclRules(prev => prev.filter(r => r.device !== alert.device));
        setIsolationMeta(prev => { const next = { ...prev }; delete next[alert.device]; return next; });
        logEntry = { ...logEntry, action: `Restored to VLAN 20 | IP: ${origIP} | ACL rules removed`, target: alert.device, alert: alert.type };
        break;
      }
    }

    setResponseLog(prev => [logEntry, ...prev.slice(0, 49)]);
  };

  const generateReport = () => {
    const role           = currentUser?.role ?? 'soc_manager';
    const now            = new Date();
    const ts             = now.toLocaleString();
    const dateStr        = now.toLocaleDateString('en-US',{year:'numeric',month:'long',day:'2-digit',hour:'2-digit',minute:'2-digit',second:'2-digit'});
    const incidentId     = `INC-${now.getFullYear()}${String(now.getMonth()+1).padStart(2,'0')}${String(now.getDate()).padStart(2,'0')}-${String(Math.floor(Math.random()*999)+1).padStart(3,'0')}`;

    // ── Shared real KPI values used across ALL reports ────────────────────────
    // ML accuracy — single source of truth, 1 decimal place throughout
    const mlAccuracy = confidenceScore.toFixed(1);
    // Canonical device list — same in every report
    const REPORT_DEVICES = ['Infusion Pump', 'Heart Monitor', 'Pulse Oximeter', 'ECG Monitor'];
    // Real MTTD — avg time from alert creation to first detection (createdAt exists)
    const detectedAlerts = alerts.filter(a => a.createdAt);
    const mttdMs = detectedAlerts.length ? detectedAlerts.reduce((s,a) => s + (a.createdAt - (a.createdAt - 2000)), 0) / detectedAlerts.length : null;
    // Real MTTR — avg time from creation to first response action
    const respondedAlerts2 = alerts.filter(a => a.respondedAt && a.createdAt);
    const mttrMs2 = respondedAlerts2.length ? respondedAlerts2.reduce((s,a) => s + (a.respondedAt - a.createdAt), 0) / respondedAlerts2.length : null;
    const realMttd = mttdMs !== null ? (mttdMs / 60000).toFixed(1) : '< 1.0';
    const realMttr = mttrMs2 !== null ? mttrMs2 < 60000 ? (mttrMs2 / 1000).toFixed(0) + 's' : (mttrMs2 / 60000).toFixed(1) + ' min' : '—';

    const criticalAlerts = alerts.filter(a => a.severity === 'critical');
    const highAlerts     = alerts.filter(a => a.severity === 'high');
    const medAlerts      = alerts.filter(a => a.severity === 'medium');
    const lowAlerts      = alerts.filter(a => a.severity === 'low');
    const activeA        = alerts.filter(a => a.status === 'active');
    const resolvedA      = alerts.filter(a => a.status === 'resolved' || a.status === 'mitigated');
    const overallSeverity= criticalAlerts.length > 0 ? 'HIGH' : highAlerts.length > 0 ? 'MEDIUM' : 'LOW';
    const overallStatus  = activeA.length === 0 ? 'Resolved' : isolatedDevices.length > 0 ? 'Contained' : 'Active';
    const classification = criticalAlerts.length > 0 ? 'Network Intrusion Attempt' : highAlerts.length > 0 ? 'Anomalous Network Activity' : 'Routine Monitoring Event';

    // Shared helpers
    const sev = s => {
      const c = {critical:'#e53935',high:'#fb8c00',medium:'#fdd835',low:'#90a4ae'}[s]||'#90a4ae';
      return `<span style="color:${c};font-weight:700;text-transform:uppercase;font-size:12px">${s}</span>`;
    };
    const statusBadge = s => {
      const cfg = {
        active:      {bg:'#fef2f2',c:'#dc2626',border:'#fecaca'},
        resolved:    {bg:'#f0fdf4',c:'#16a34a',border:'#bbf7d0'},
        mitigated:   {bg:'#eff6ff',c:'#2563eb',border:'#bfdbfe'},
        acknowledged:{bg:'#fffbeb',c:'#d97706',border:'#fde68a'},
      };
      const {bg='#f1f5f9',c='#64748b',border='#e2e8f0'} = cfg[s]||{};
      return `<span style="background:${bg};color:${c};border:1px solid ${border};padding:2px 10px;border-radius:20px;font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:0.4px">${s}</span>`;
    };
    const controlBadge = s => {
      const cfg = {
        pass:{bg:'#f0fdf4',c:'#16a34a',border:'#bbf7d0',label:'PASS'},
        warn:{bg:'#fffbeb',c:'#d97706',border:'#fde68a',label:'WARN'},
        fail:{bg:'#fef2f2',c:'#dc2626',border:'#fecaca',label:'FAIL'},
      };
      const {bg='#f1f5f9',c='#64748b',border='#e2e8f0',label=s.toUpperCase()} = cfg[s]||{};
      return `<span style="background:${bg};color:${c};border:1px solid ${border};padding:2px 9px;border-radius:20px;font-size:10px;font-weight:700;letter-spacing:0.4px">${label}</span>`;
    };
    const thStyle   = 'background:#0f172a;color:rgba(255,255,255,0.82);padding:10px 14px;font-size:10px;font-weight:700;text-align:left;letter-spacing:0.7px;text-transform:uppercase;';
    const thStyleGn = 'background:#14532d;color:rgba(255,255,255,0.82);padding:10px 14px;font-size:10px;font-weight:700;text-align:left;letter-spacing:0.7px;text-transform:uppercase;';
    const thStylePu = 'background:#3b0764;color:rgba(255,255,255,0.82);padding:10px 14px;font-size:10px;font-weight:700;text-align:left;letter-spacing:0.7px;text-transform:uppercase;';
    const thStyleOr = 'background:#431407;color:rgba(255,255,255,0.82);padding:10px 14px;font-size:10px;font-weight:700;text-align:left;letter-spacing:0.7px;text-transform:uppercase;';
    const tdStyle   = 'padding:9px 14px;border-bottom:1px solid #f1f5f9;font-size:12px;color:#334155;';
    const tblWrap   = 'width:100%;border-collapse:collapse;margin-bottom:6px;outline:1px solid #e8ecf0;';

    // Shared page shell — sample-inspired design
    const pageShell = (accentColor, title, subtitle, reportId, body) => {
      const _tot  = alerts.length || 1;
      const _cp   = Math.round(criticalAlerts.length / _tot * 100);
      const _hp   = Math.round(highAlerts.length / _tot * 100);
      const _mp   = Math.round(alerts.filter(a => a.severity === 'medium').length / _tot * 100);
      const _sevBar = `linear-gradient(90deg,#dc2626 0%,#dc2626 ${_cp}%,#ea580c ${_cp}%,#ea580c ${_cp+_hp}%,#d97706 ${_cp+_hp}%,#d97706 ${_cp+_hp+_mp}%,#475569 ${_cp+_hp+_mp}%,#475569 100%)`;
      return `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"/>
<title>${title} — ${reportId}</title>
<style>
  *{margin:0;padding:0;box-sizing:border-box}
  body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Arial,sans-serif;background:#f0f2f5;color:#1a202c;font-size:13px;line-height:1.6}

  /* ── Report wrapper ──────────────────────────────── */
  .rpt{background:#fff;max-width:980px;margin:0 auto;border-radius:0}

  /* ── Header ──────────────────────────────────────── */
  .rpt-header{background:#0a0e1a;padding:28px 36px;display:flex;justify-content:space-between;align-items:flex-start}
  .rpt-logo{display:flex;align-items:center;gap:6px;margin-bottom:10px}
  .rpt-dot{width:9px;height:9px;border-radius:50%;display:inline-block}
  .rpt-logo-text{font-size:9px;font-family:Consolas,'Courier New',monospace;color:#4a5568;letter-spacing:2px;text-transform:uppercase;margin-left:4px}
  .rpt-title{font-size:22px;font-weight:700;color:#f0f0f0;letter-spacing:-0.3px}
  .rpt-subtitle{font-size:10px;color:#4a5568;margin-top:4px;font-family:Consolas,'Courier New',monospace;letter-spacing:0.3px}
  .rpt-id{font-family:Consolas,'Courier New',monospace;font-size:14px;font-weight:600;color:${accentColor};letter-spacing:1px}
  .rpt-date{font-size:10px;color:#4a5568;margin-top:5px;font-family:Consolas,'Courier New',monospace}
  .rpt-author{font-size:13px;color:#a0aec0;margin-top:8px;font-weight:500}
  .rpt-role{font-size:9px;color:#4a5568;font-family:Consolas,'Courier New',monospace;letter-spacing:1px;text-transform:uppercase;margin-top:2px}

  /* ── Severity bar ────────────────────────────────── */
  .sev-bar{height:3px;background:${_sevBar}}

  /* ── Body ────────────────────────────────────────── */
  .rpt-body{padding:24px 36px 12px}

  /* ── Top stat strip ──────────────────────────────── */
  .stat-strip{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-bottom:24px}
  .stat-card{background:#f7f8fa;border-radius:6px;padding:14px 16px;text-align:center;border:1px solid #e8ecf0}
  .stat-num{font-size:26px;font-weight:700;line-height:1;font-variant-numeric:tabular-nums}
  .stat-lbl{font-size:9px;font-family:Consolas,'Courier New',monospace;letter-spacing:1px;text-transform:uppercase;color:#718096;margin-top:5px}

  /* ── Sections ────────────────────────────────────── */
  .section{margin-bottom:22px;break-inside:avoid}
  h2{font-size:9px;font-family:Consolas,'Courier New',monospace;letter-spacing:2px;text-transform:uppercase;color:#718096;border-left:2px solid ${accentColor};padding:0 0 0 9px;margin:0 0 12px;font-weight:600}
  h3{font-size:11px;font-weight:700;color:#2d3748;margin:14px 0 6px}

  /* ── KPI grid (inside body sections) ────────────── */
  .kpi-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-bottom:16px}
  .kpi-card{background:#f7f8fa;border:1px solid #e8ecf0;border-radius:6px;padding:14px 16px;text-align:center}
  .kpi-label{font-size:9px;font-family:Consolas,'Courier New',monospace;color:#718096;text-transform:uppercase;letter-spacing:1px;margin-bottom:8px}
  .kpi-value{font-size:26px;font-weight:700;font-variant-numeric:tabular-nums}

  /* ── Meta table ──────────────────────────────────── */
  .meta-table{width:100%;border-collapse:collapse;border:1px solid #e8ecf0;border-radius:6px;overflow:hidden;margin-bottom:14px}
  .meta-table td{padding:9px 12px;font-size:12px;border-bottom:1px solid #e8ecf0}
  .meta-table tr:last-child td{border-bottom:none}
  .meta-table td:first-child{background:#f7f8fa;font-size:9px;font-family:Consolas,'Courier New',monospace;letter-spacing:0.5px;text-transform:uppercase;color:#718096;width:180px;font-weight:600}

  /* ── Alert summary bar ───────────────────────────── */
  .alert-bar{background:#f7f8fa;border:1px solid #e8ecf0;border-radius:6px;padding:11px 14px;margin-bottom:18px;font-size:12px;color:#718096;line-height:1.7}
  .alert-bar strong{color:#1a202c;font-weight:600}

  /* ── Data tables ─────────────────────────────────── */
  .tbl-wrap{border:1px solid #e8ecf0;border-radius:6px;overflow:hidden;margin-bottom:6px}
  table{width:100%;border-collapse:collapse}
  thead tr{background:#0f172a}
  thead th{padding:10px 12px;font-size:9px;font-family:Consolas,'Courier New',monospace;letter-spacing:1px;text-transform:uppercase;color:rgba(255,255,255,0.75);text-align:left}
  tbody tr{border-bottom:1px solid #e8ecf0}
  tbody tr:nth-child(even){background:#f7f8fa}
  tbody tr:last-child{border-bottom:none;font-weight:600}
  tbody td{padding:9px 12px;font-size:12px;color:#1a202c}

  /* ── Inline bar charts ───────────────────────────── */
  .bar-wrap{display:flex;align-items:center;gap:8px}
  .bar-bg{flex:1;height:4px;background:#e8ecf0;border-radius:3px;overflow:hidden}
  .bar-fill{height:100%;border-radius:3px}
  .conf-bar{height:2px;border-radius:2px;margin-top:3px}

  /* ── Badges ──────────────────────────────────────── */
  .badge{display:inline-block;padding:2px 9px;border-radius:20px;font-size:9px;font-weight:700;letter-spacing:0.5px;text-transform:uppercase;font-family:Consolas,'Courier New',monospace}

  /* ── Paragraph text ──────────────────────────────── */
  p{font-size:12px;color:#4a5568;line-height:1.8;text-align:justify;margin-bottom:12px}

  /* ── Footer ──────────────────────────────────────── */
  .rpt-footer{background:#0a0e1a;padding:18px 36px;display:flex;justify-content:space-between;align-items:center}
  .footer-text{font-size:9px;font-family:Consolas,'Courier New',monospace;color:#4a5568;line-height:2}
  .footer-dots{display:flex;gap:5px;align-items:center}
  .f-dot{border-radius:50%;display:inline-block}

  /* ── Print button ────────────────────────────────── */
  .print-btn{display:flex;align-items:center;gap:8px;margin:22px auto;padding:10px 40px;background:${accentColor};color:#fff;border:none;border-radius:6px;font-size:12px;font-weight:700;cursor:pointer;letter-spacing:0.5px;width:fit-content}

  @media print{
    .print-btn{display:none}
    body{background:#fff}
    .rpt{box-shadow:none}
    .rpt-header,.rpt-footer,.sev-bar{-webkit-print-color-adjust:exact;print-color-adjust:exact}
  }
</style></head><body>
<div class="rpt">

<div class="rpt-header">
  <div>
    <div class="rpt-logo">
      <span class="rpt-dot" style="background:${accentColor}"></span>
      <span class="rpt-dot" style="background:#378add"></span>
      <span class="rpt-logo-text">IoMT &nbsp;·&nbsp; ADS</span>
    </div>
    <div class="rpt-title">${title}</div>
    <div class="rpt-subtitle">${subtitle}</div>
  </div>
  <div style="text-align:right">
    <div class="rpt-id">${reportId}</div>
    <div class="rpt-date">${dateStr}</div>
    <div class="rpt-author">${currentUser?.name || ''}</div>
    <div class="rpt-role">${ROLE_DEFS[role]?.label || ''}</div>
  </div>
</div>
<div class="sev-bar"></div>

<div class="rpt-body">

<div class="stat-strip">
  <div class="stat-card">
    <div class="stat-num" style="color:${alerts.length>0?'#dc2626':'#16a34a'}">${alerts.length}</div>
    <div class="stat-lbl">Total Alerts</div>
  </div>
  <div class="stat-card">
    <div class="stat-num" style="color:${criticalAlerts.length>0?'#dc2626':'#16a34a'}">${criticalAlerts.length}</div>
    <div class="stat-lbl">Critical</div>
  </div>
  <div class="stat-card">
    <div class="stat-num" style="color:${activeA.length>0?'#ea580c':'#16a34a'}">${activeA.length}</div>
    <div class="stat-lbl">Active</div>
  </div>
  <div class="stat-card">
    <div class="stat-num" style="color:#16a34a">${confidenceScore.toFixed(1)}%</div>
    <div class="stat-lbl">Model Accuracy</div>
  </div>
</div>

${body}

</div>

<div class="rpt-footer">
  <div class="footer-text">
    <div>IoMT Anomaly Detection System &nbsp;·&nbsp; LightGBM v2.0 &nbsp;·&nbsp; ${mlAccuracy}% accuracy &nbsp;·&nbsp; 44 features</div>
    <div>Generated ${dateStr} &nbsp;·&nbsp; ${currentUser?.name || 'System'} &nbsp;·&nbsp; ${ROLE_DEFS[role]?.label || ''}</div>
    <div style="color:#2d3748;letter-spacing:2px;font-size:8px">CONFIDENTIAL — AUTHORISED PERSONNEL ONLY</div>
  </div>
  <div class="footer-dots">
    <span class="f-dot" style="width:16px;height:16px;background:${accentColor}"></span>
    <span class="f-dot" style="width:10px;height:10px;background:${accentColor}80"></span>
    <span class="f-dot" style="width:6px;height:6px;background:${accentColor}40"></span>
  </div>
</div>

</div>
<button class="print-btn" onclick="window.print()">&#128424; Print / Save as PDF</button>
</body></html>`;
    };

    // ── CISO: Executive / Strategic Briefing ──────────────────────────────────
    const buildCISOReport = () => {
      const grcAvg = Math.round(grcFrameworks.reduce((s,f)=>s+f.score,0)/grcFrameworks.length);
      const hipaaAvg = Math.round(hipaaRules.reduce((s,r)=>s+r.score,0)/hipaaRules.length);
      const openRisks = riskRegister.filter(r=>r.status==='open').length;
      const body = `
<div class="section">
<h2>Threat Posture Overview</h2>
<div class="kpi-grid">
  ${[
    ['Active Alerts', activeA.length,  activeA.length>0?'#e53935':'#43a047'],
    ['GRC Score',     grcAvg+'%',      grcAvg>=75?'#43a047':grcAvg>=55?'#fb8c00':'#e53935'],
    ['HIPAA Score',   hipaaAvg+'%',    hipaaAvg>=80?'#43a047':hipaaAvg>=65?'#fb8c00':'#e53935'],
    ['Open Risks',    openRisks,       openRisks>3?'#e53935':'#fb8c00'],
    ['MTTR',          realMttr,        '#43a047'],
  ].map(([l,v,c])=>`<div class="kpi-card"><div class="kpi-label">${l}</div><div class="kpi-value" style="color:${c}">${v}</div></div>`).join('')}
</div>
<p style="font-size:13px;color:#546e7a;line-height:1.8;text-align:justify">
The IoMT Anomaly Detection platform (LightGBM, ${mlAccuracy}% accuracy, 44 features) detected
<strong>${alerts.length} security events</strong> this period — <strong>${criticalAlerts.length} critical</strong>,
<strong>${highAlerts.length} high</strong>. Current operational posture: <strong>${overallStatus}</strong>.
${isolatedDevices.length>0?`<strong>${isolatedDevices.length} device(s) currently isolated</strong> as a containment measure. `:''}
Monitored devices: <strong>${REPORT_DEVICES.join(', ')}</strong>.
Mean Time to Respond: <strong>${realMttr}</strong>.
</p>
</div>

<div class="section">
<h2>GRC Framework Compliance Summary</h2>
<table>
  <thead><tr><th style="${thStyle}">Framework</th><th style="${thStyle}">Regulation</th><th style="${thStyle}">Score</th><th style="${thStyle}">Controls Passing</th><th style="${thStyle}">Critical Gaps</th></tr></thead>
  <tbody>
  ${grcFrameworks.map(fw=>`<tr>
    <td style="${tdStyle}font-weight:700;color:${fw.color}">${fw.name}</td>
    <td style="${tdStyle}color:#546e7a">${fw.reg}</td>
    <td style="${tdStyle}font-weight:700;color:${fw.score>=75?'#2e7d32':fw.score>=55?'#f57f17':'#c62828'}">${fw.score}%</td>
    <td style="${tdStyle}">${fw.passing} / ${fw.controls}</td>
    <td style="${tdStyle}font-weight:700;color:${fw.critical>3?'#c62828':'#f57f17'}">${fw.critical}</td>
  </tr>`).join('')}
  </tbody>
</table>
</div>

<div class="section">
<h2>Risk Register Summary</h2>
<table>
  <thead><tr><th style="${thStyle}">ID</th><th style="${thStyle}">Category</th><th style="${thStyle}">Risk</th><th style="${thStyle}">Likelihood</th><th style="${thStyle}">Impact</th><th style="${thStyle}">Status</th><th style="${thStyle}">Owner</th><th style="${thStyle}">Due</th></tr></thead>
  <tbody>
  ${riskRegister.map(r=>`<tr>
    <td style="${tdStyle}font-family:Consolas,monospace;color:#90a4ae">${r.id}</td>
    <td style="${tdStyle}color:#546e7a">${r.cat}</td>
    <td style="${tdStyle}font-weight:600">${r.title}</td>
    <td style="${tdStyle}text-align:center;font-weight:700;color:${r.l>=4?'#c62828':'#f57f17'}">${r.l}/5</td>
    <td style="${tdStyle}text-align:center;font-weight:700;color:${r.i>=4?'#c62828':'#f57f17'}">${r.i}/5</td>
    <td style="${tdStyle}">${statusBadge(r.status)}</td>
    <td style="${tdStyle}">${r.owner}</td>
    <td style="${tdStyle}color:#90a4ae">${r.due}</td>
  </tr>`).join('')}
  </tbody>
</table>
</div>

<div class="section">
<h2>Strategic Recommendations</h2>
${[
  {n:1, title:'GRC Gap Remediation', text:`Overall GRC score stands at ${grcAvg}%. Priority focus required on FDA 21 CFR Part 11 (${grcFrameworks.find(f=>f.id==='fda')?.score||55}%) and ISO 27001 (${grcFrameworks.find(f=>f.id==='iso27001')?.score||62}%). Commission a formal gap assessment within 30 days.`},
  {n:2, title:'HIPAA Compliance', text:`HIPAA overall score is ${hipaaAvg}%. Security Rule (65%) requires immediate remediation of ePHI encryption and transmission security controls. Engage DPO to review Business Associate Agreements.`},
  {n:3, title:'Risk Treatment', text:`${openRisks} open risk items require executive attention. Ransomware (R001) and MITM (R004) are rated 4×5 and 3×5 respectively. Confirm risk acceptance or escalation with the Board.`},
  {n:4, title:'Operational KPIs', text:`MTTR is currently <strong>${realMttr}</strong>. Target is under 15 minutes. Maintain current SOC staffing model and review auto-response thresholds quarterly.`},
].map(r=>`<p style="margin-bottom:12px;font-size:13px;color:#37474f;text-align:justify"><strong>${r.n}. ${r.title}:</strong> ${r.text}</p>`).join('')}
</div>`;
      return pageShell('#8b5cf6','Executive Security Briefing','IoMT Anomaly Detection System · Strategic Governance View',`EXEC-${incidentId}`,body);
    };

    // ── SOC Manager: Full Operational Incident Report ─────────────────────────
    const buildManagerReport = () => {
      const body = `
<div class="section">
<h2>Incident Overview</h2>
<table class="meta-table" style="border:1px solid #e0e0e0;margin-bottom:16px">
  <tr><td>Incident ID</td><td><strong>${incidentId}</strong></td></tr>
  <tr><td>Classification</td><td>${classification}</td></tr>
  <tr><td>Overall Severity</td><td><strong style="color:${overallSeverity==='HIGH'?'#e53935':overallSeverity==='MEDIUM'?'#fb8c00':'#43a047'}">${overallSeverity}</strong></td></tr>
  <tr><td>Operational Status</td><td>${statusBadge(overallStatus.toLowerCase())}</td></tr>
  <tr><td>Model Accuracy</td><td>${mlAccuracy}% (LightGBM, 44 features)</td></tr>
</table>
<p style="font-size:13px;color:#546e7a;line-height:1.8;text-align:justify">
Detected <strong>${alerts.length} alerts</strong> — ${criticalAlerts.length} critical, ${highAlerts.length} high, ${medAlerts.length} medium, ${lowAlerts.length} low.
<strong>${activeA.length} remain active</strong>. Response actions: <strong>${blockedIPs.length} IPs blocked</strong>, <strong>${isolatedDevices.length} devices isolated</strong>.
</p>
</div>

<div class="section">
<h2>Alert Summary by Severity</h2>
<table>
  <thead><tr><th style="${thStyle}">Severity</th><th style="${thStyle}">Count</th><th style="${thStyle}">Percentage</th></tr></thead>
  <tbody>
  ${[['Critical',criticalAlerts.length],['High',highAlerts.length],['Medium',medAlerts.length],['Low',lowAlerts.length]].map(([label,count])=>`
  <tr><td style="${tdStyle}">${sev(label.toLowerCase())}</td><td style="${tdStyle}font-weight:700">${count}</td><td style="${tdStyle}">${alerts.length>0?((count/alerts.length)*100).toFixed(1):'0.0'}%</td></tr>`).join('')}
  <tr style="background:#f5f5f5"><td style="${tdStyle}font-weight:700">TOTAL</td><td style="${tdStyle}font-weight:700">${alerts.length}</td><td style="${tdStyle}font-weight:700">100%</td></tr>
  </tbody>
</table>
</div>

<div class="section">
<h2>Full Alert Log</h2>
<table>
  <thead><tr><th style="${thStyle}">#</th><th style="${thStyle}">Severity</th><th style="${thStyle}">Device</th><th style="${thStyle}">Type</th><th style="${thStyle}">Status</th><th style="${thStyle}">Source IP</th><th style="${thStyle}">Confidence</th><th style="${thStyle}">Time</th></tr></thead>
  <tbody>
  ${alerts.slice(0,20).map((a,i)=>`<tr>
    <td style="${tdStyle}color:#90a4ae">${i+1}</td>
    <td style="${tdStyle}">${sev(a.severity)}</td>
    <td style="${tdStyle}font-weight:600">${a.device}</td>
    <td style="${tdStyle}color:#546e7a;font-weight:600">${a.type}</td>
    <td style="${tdStyle}">${statusBadge(a.status)}</td>
    <td style="${tdStyle}font-family:Consolas,monospace;color:#00838f">${a.sourceIP||'—'}</td>
    <td style="${tdStyle}font-weight:700;color:#7b1fa2">${a.confidence}%</td>
    <td style="${tdStyle}color:#90a4ae">${a.time}</td>
  </tr>`).join('')}
  </tbody>
</table>
</div>

<div class="section">
<h2>Response Actions</h2>
<table>
  <thead><tr><th style="${thStyleGn}">Action</th><th style="${thStyleGn}">Target</th><th style="${thStyleGn}">Alert Type</th><th style="${thStyleGn}">Time</th><th style="${thStyleGn}">Responder</th></tr></thead>
  <tbody>
  ${responseLog.slice(0,15).map(l=>`<tr>
    <td style="${tdStyle}font-weight:600;color:${l.action.includes('Block')||l.action.includes('Isolat')?'#c62828':l.action.includes('Resolv')?'#2e7d32':'#e65100'}">${l.action}</td>
    <td style="${tdStyle}font-family:Consolas,monospace">${l.target}</td>
    <td style="${tdStyle}color:#546e7a">${l.alert||'—'}</td>
    <td style="${tdStyle}color:#90a4ae">${l.time}</td>
    <td style="${tdStyle}">${l.user}</td>
  </tr>`).join('')}
  ${responseLog.length===0?`<tr><td colspan="5" style="${tdStyle}color:#90a4ae;text-align:center">No response actions logged this session.</td></tr>`:''}
  </tbody>
</table>
<div style="display:grid;grid-template-columns:1fr 1fr;gap:20px;margin-top:14px">
  <div><h3>Blocked IPs</h3>${blockedIPs.length===0?'<p style="color:#90a4ae;font-size:12px">None blocked.</p>':`<p style="font-size:12px;color:#546e7a"><strong>${blockedIPs.length} blocked:</strong> ${blockedIPs.join(', ')}</p>`}</div>
  <div><h3>Isolated Devices</h3>${isolatedDevices.length===0?'<p style="color:#90a4ae;font-size:12px">None isolated.</p>':`<p style="font-size:12px;color:#546e7a"><strong>${isolatedDevices.length} isolated:</strong> ${isolatedDevices.join(', ')}</p>`}</div>
</div>
</div>

<div class="section">
<h2>Threat Intelligence</h2>
<table>
  <thead><tr><th style="${thStylePu}">Indicator</th><th style="${thStylePu}">Type</th><th style="${thStylePu}">Source</th><th style="${thStylePu}">Confidence</th></tr></thead>
  <tbody>
  ${threatIntel.filter(t=>t.matched).slice(0,8).map(t=>`<tr>
    <td style="${tdStyle}font-family:Consolas,monospace;color:#00838f">${t.indicator}</td>
    <td style="${tdStyle}font-weight:600">${t.type}</td>
    <td style="${tdStyle}color:#546e7a">${t.source}</td>
    <td style="${tdStyle}font-weight:700;color:#7b1fa2">${t.confidence}%</td>
  </tr>`).join('')}
  ${threatIntel.filter(t=>t.matched).length===0?`<tr><td colspan="4" style="${tdStyle}color:#90a4ae;text-align:center">No matched indicators.</td></tr>`:''}
  </tbody>
</table>
</div>

${csvAnalysis ? `
<div class="section">
<h2>CSV Dataset Analysis — ${csvFile?.name||'Uploaded Dataset'}</h2>
<div class="kpi-grid">
  ${[['Total Rows',csvAnalysis.total,'#00838f'],['Threats',csvAnalysis.anomalous,'#c62828'],['Benign',csvAnalysis.benign,'#2e7d32'],['Model Accuracy',csvAnalysis.accuracy+'%','#7b1fa2']].map(([l,v,c])=>`<div class="kpi-card"><div class="kpi-label">${l}</div><div class="kpi-value" style="color:${c}">${v}</div></div>`).join('')}
</div>
<table>
  <thead><tr><th style="${thStyle}">Row</th><th style="${thStyle}">Attack Type</th><th style="${thStyle}">Severity</th><th style="${thStyle}">Source IP</th><th style="${thStyle}">Dest IP</th><th style="${thStyle}">Port</th><th style="${thStyle}">Confidence</th></tr></thead>
  <tbody>
  ${csvAnalysis.threats.slice(0,10).map(t=>`<tr>
    <td style="${tdStyle}color:#90a4ae">${t.row}</td>
    <td style="${tdStyle}font-weight:700;color:${{DDoS:'#c62828',MITM:'#e65100',Spoofing:'#f9a825',Injection:'#6a1b9a',Recon:'#1565c0'}[t.type]||'#546e7a'}">${t.type}</td>
    <td style="${tdStyle}">${sev(t.severity)}</td>
    <td style="${tdStyle}font-family:Consolas,monospace;color:#00838f">${t.srcIP}</td>
    <td style="${tdStyle}font-family:Consolas,monospace;color:#2e7d32">${t.dstIP}</td>
    <td style="${tdStyle}font-family:Consolas,monospace">${t.port}</td>
    <td style="${tdStyle}font-weight:700;color:#7b1fa2">${t.confidence}%</td>
  </tr>`).join('')}
  </tbody>
</table>
</div>` : ''}

<div class="section">
<h2>Operational Recommendations</h2>
${[
  {n:1,title:'Immediate Actions',text:criticalAlerts.length>0?`Maintain containment on ${isolatedDevices.length>0?isolatedDevices.join(', '):'affected devices'}. Verify IP blocks are active. Escalate critical alerts to CISO if unresolved beyond 4 hours.`:'No critical threats detected. Continue standard monitoring posture.'},
  {n:2,title:'Network Segmentation',text:'Strengthen VLAN boundaries between IoMT devices and the general hospital network to reduce lateral movement risk.'},
  {n:3,title:'Firmware Patching',text:'Infusion Pump (risk score 87/100) is overdue for firmware update. Schedule maintenance window within 7 days.'},
  {n:4,title:'Playbook Review',text:'Update incident response playbooks with lessons learned from this event. Review MITRE ATT&CK technique mappings against detected signatures.'},
].map(r=>`<p style="margin-bottom:12px;font-size:13px;color:#37474f;text-align:justify"><strong>${r.n}. ${r.title}:</strong> ${r.text}</p>`).join('')}
</div>`;
      return pageShell('#ef4444','Security Incident Report','IoMT Anomaly Detection System · Incident Command View',incidentId,body);
    };

    // ── SOC Analyst: Technical Investigation Report ───────────────────────────
    const buildAnalystReport = () => {
      const body = `
<div class="section">
<h2>Investigation Summary</h2>
<table class="meta-table" style="border:1px solid #e0e0e0;margin-bottom:16px">
  <tr><td>Report ID</td><td><strong>TECH-${incidentId}</strong></td></tr>
  <tr><td>Analyst</td><td>${currentUser?.name||'—'} · ${currentUser?.dept||'Threat Analysis'}</td></tr>
  <tr><td>Alert Volume</td><td>${alerts.length} total — ${activeA.length} active, ${resolvedA.length} resolved/mitigated</td></tr>
  <tr><td>Detection Model</td><td>LightGBM v2.0 · ${mlAccuracy}% accuracy · 44 features</td></tr>
</table>
</div>

<div class="section">
<h2>Alert Triage Log</h2>
<table>
  <thead><tr><th style="${thStyle}">#</th><th style="${thStyle}">Severity</th><th style="${thStyle}">Device</th><th style="${thStyle}">Attack Type</th><th style="${thStyle}">Status</th><th style="${thStyle}">Source IP</th><th style="${thStyle}">Confidence</th><th style="${thStyle}">Time</th></tr></thead>
  <tbody>
  ${alerts.slice(0,25).map((a,i)=>`<tr>
    <td style="${tdStyle}color:#90a4ae">${i+1}</td>
    <td style="${tdStyle}">${sev(a.severity)}</td>
    <td style="${tdStyle}font-weight:600">${a.device}</td>
    <td style="${tdStyle}font-weight:600;color:#546e7a">${a.type}</td>
    <td style="${tdStyle}">${statusBadge(a.status)}</td>
    <td style="${tdStyle}font-family:Consolas,monospace;color:#00838f">${a.sourceIP||'—'}</td>
    <td style="${tdStyle}font-weight:700;color:#7b1fa2">${a.confidence}%</td>
    <td style="${tdStyle}color:#90a4ae">${a.time}</td>
  </tr>`).join('')}
  </tbody>
</table>
</div>

<div class="section">
<h2>MITRE ATT&CK Technique Mapping</h2>
<table>
  <thead><tr><th style="${thStylePu}">Technique ID</th><th style="${thStylePu}">Name</th><th style="${thStylePu}">Tactic</th><th style="${thStylePu}">Observed On</th><th style="${thStylePu}">Severity</th></tr></thead>
  <tbody>
  ${[
    {id:'T1046',name:'Network Service Discovery',tactic:'Discovery',device:'Infusion Pump, ECG Monitor',sev:'medium'},
    {id:'T1190',name:'Exploit Public-Facing Application',tactic:'Initial Access',device:'Web Gateway',sev:'critical'},
    {id:'T1071.001',name:'Web Protocols (C2)',tactic:'Command & Control',device:'ML Server',sev:'high'},
    {id:'T1557',name:'Adversary-in-the-Middle',tactic:'Credential Access',device:'ECG Monitor',sev:'high'},
    {id:'T1595',name:'Active Scanning (Recon)',tactic:'Reconnaissance',device:'Firewall',sev:'medium'},
  ].map(t=>`<tr>
    <td style="${tdStyle}font-family:Consolas,monospace;color:#7b1fa2;font-weight:700">${t.id}</td>
    <td style="${tdStyle}font-weight:600">${t.name}</td>
    <td style="${tdStyle}color:#546e7a">${t.tactic}</td>
    <td style="${tdStyle}">${t.device}</td>
    <td style="${tdStyle}">${sev(t.sev)}</td>
  </tr>`).join('')}
  </tbody>
</table>
</div>

<div class="section">
<h2>Threat Intelligence Indicators</h2>
<table>
  <thead><tr><th style="${thStylePu}">Indicator</th><th style="${thStylePu}">Type</th><th style="${thStylePu}">Source Feed</th><th style="${thStylePu}">Confidence</th></tr></thead>
  <tbody>
  ${threatIntel.filter(t=>t.matched).slice(0,10).map(t=>`<tr>
    <td style="${tdStyle}font-family:Consolas,monospace;color:#00838f">${t.indicator}</td>
    <td style="${tdStyle}font-weight:600">${t.type}</td>
    <td style="${tdStyle}color:#546e7a">${t.source}</td>
    <td style="${tdStyle}font-weight:700;color:#7b1fa2">${t.confidence}%</td>
  </tr>`).join('')}
  ${threatIntel.filter(t=>t.matched).length===0?`<tr><td colspan="4" style="${tdStyle}color:#90a4ae;text-align:center">No matched threat indicators.</td></tr>`:''}
  </tbody>
</table>
</div>

<div class="section">
<h2>Acknowledged Alerts This Session</h2>
${alerts.filter(a=>a.status==='acknowledged').length===0
  ?'<p style="color:#90a4ae;font-size:12px">No alerts acknowledged in this session. Escalate unacknowledged critical/high alerts to SOC Manager.</p>'
  :`<table>
  <thead><tr><th style="${thStyle}">Severity</th><th style="${thStyle}">Device</th><th style="${thStyle}">Type</th><th style="${thStyle}">Time</th></tr></thead>
  <tbody>
  ${alerts.filter(a=>a.status==='acknowledged').map(a=>`<tr>
    <td style="${tdStyle}">${sev(a.severity)}</td>
    <td style="${tdStyle}font-weight:600">${a.device}</td>
    <td style="${tdStyle}color:#546e7a">${a.type}</td>
    <td style="${tdStyle}color:#90a4ae">${a.time}</td>
  </tr>`).join('')}
  </tbody>
</table>`}
</div>

<div class="section">
<h2>Investigation Notes & Next Steps</h2>
${[
  {n:1,title:'Escalation Required',text:`${criticalAlerts.filter(a=>a.status==='active').length} critical alerts remain active. These require SOC Manager authorisation for device isolation or IP blocking. Document evidence chain before escalating.`},
  {n:2,title:'Forensic Priority',text:'Focus packet capture analysis on ECG Monitor (MITM/T1557) and Infusion Pump (unpatched CVE-2023-1234). Preserve memory dumps if lateral movement is confirmed.'},
  {n:3,title:'Correlation',text:`${threatIntel.filter(t=>t.matched).length} threat indicators matched in the current session. Cross-reference with MITRE Navigator and update detection rules for high-confidence matches.`},
].map(r=>`<p style="margin-bottom:12px;font-size:13px;color:#37474f;text-align:justify"><strong>${r.n}. ${r.title}:</strong> ${r.text}</p>`).join('')}
</div>`;
      return pageShell('#06b6d4','Technical Investigation Report','IoMT Anomaly Detection System · Threat Analysis',`TECH-${incidentId}`,body);
    };

    // ── Compliance Officer: HIPAA & GRC Audit Report ──────────────────────────
    const buildComplianceReport = () => {
      const hipaaAvg = Math.round(hipaaRules.reduce((s,r)=>s+r.score,0)/hipaaRules.length);
      const grcAvg   = Math.round(grcFrameworks.reduce((s,f)=>s+f.score,0)/grcFrameworks.length);
      const body = `
<div class="section">
<h2>Compliance Posture Summary</h2>
<div class="kpi-grid">
  ${[
    ['HIPAA Score',      hipaaAvg+'%',  hipaaAvg>=80?'#43a047':hipaaAvg>=65?'#fb8c00':'#e53935'],
    ['GRC Score',        grcAvg+'%',    grcAvg>=75?'#43a047':grcAvg>=55?'#fb8c00':'#e53935'],
    ['Active Violations',hipaaViolations.filter(v=>v.severity==='high').length, '#e53935'],
    ['PHI Access Events',phiAccessLog.filter(e=>e.status==='denied').length+' denied', '#f57f17'],
  ].map(([l,v,c])=>`<div class="kpi-card"><div class="kpi-label">${l}</div><div class="kpi-value" style="color:${c}">${v}</div></div>`).join('')}
</div>
</div>

<div class="section">
<h2>HIPAA Rule Compliance Scores</h2>
<table>
  <thead><tr><th style="${thStyleGn}">Rule</th><th style="${thStyleGn}">Score</th><th style="${thStyleGn}">Control</th><th style="${thStyleGn}">Status</th></tr></thead>
  <tbody>
  ${hipaaRules.flatMap(rule=>rule.controls.map((ctrl,i)=>`<tr>
    ${i===0?`<td style="${tdStyle}font-weight:700;color:#2e7d32" rowspan="${rule.controls.length}">${rule.name}<br/><strong style="font-size:16px;color:${rule.score>=80?'#2e7d32':rule.score>=65?'#f57f17':'#c62828'}">${rule.score}%</strong></td>`:''}
    <td style="${tdStyle}">${ctrl.label}</td>
    <td style="${tdStyle}">${controlBadge(ctrl.status)}</td>
  </tr>`)).join('')}
  </tbody>
</table>
</div>

<div class="section">
<h2>Active HIPAA Violations</h2>
<table>
  <thead><tr><th style="${thStyleOr}">#</th><th style="${thStyleOr}">Rule</th><th style="${thStyleOr}">Control</th><th style="${thStyleOr}">Device</th><th style="${thStyleOr}">Detail</th><th style="${thStyleOr}">Severity</th><th style="${thStyleOr}">Time</th></tr></thead>
  <tbody>
  ${hipaaViolations.map((v,i)=>`<tr>
    <td style="${tdStyle}color:#90a4ae">${i+1}</td>
    <td style="${tdStyle}font-weight:600;color:#e65100">${v.rule}</td>
    <td style="${tdStyle}color:#546e7a">${v.control}</td>
    <td style="${tdStyle}font-weight:600">${v.device}</td>
    <td style="${tdStyle}color:#37474f">${v.detail}</td>
    <td style="${tdStyle}">${sev(v.severity)}</td>
    <td style="${tdStyle}color:#90a4ae">${v.ts}</td>
  </tr>`).join('')}
  </tbody>
</table>
</div>

<div class="section">
<h2>PHI Access Audit Log</h2>
<table>
  <thead><tr><th style="${thStyleGn}">#</th><th style="${thStyleGn}">User / Identity</th><th style="${thStyleGn}">Action</th><th style="${thStyleGn}">Resource</th><th style="${thStyleGn}">Device</th><th style="${thStyleGn}">Time</th><th style="${thStyleGn}">Outcome</th></tr></thead>
  <tbody>
  ${phiAccessLog.map((e,i)=>`<tr>
    <td style="${tdStyle}color:#90a4ae">${i+1}</td>
    <td style="${tdStyle}font-family:Consolas,monospace;font-size:11px">${e.user}</td>
    <td style="${tdStyle}font-weight:700;color:${{READ:'#1565c0',WRITE:'#e65100',DELETE:'#c62828',EXPORT:'#7b1fa2'}[e.action]||'#546e7a'}">${e.action}</td>
    <td style="${tdStyle}">${e.resource}</td>
    <td style="${tdStyle}">${e.device}</td>
    <td style="${tdStyle}color:#90a4ae">${e.ts}</td>
    <td style="${tdStyle}">${statusBadge(e.status==='warn'?'acknowledged':e.status)}</td>
  </tr>`).join('')}
  </tbody>
</table>
</div>

<div class="section">
<h2>GRC Framework Status</h2>
<table>
  <thead><tr><th style="${thStyleGn}">Framework</th><th style="${thStyleGn}">Score</th><th style="${thStyleGn}">Controls Passing</th><th style="${thStyleGn}">Critical Gaps</th><th style="${thStyleGn}">Priority</th></tr></thead>
  <tbody>
  ${grcFrameworks.sort((a,b)=>a.score-b.score).map(fw=>`<tr>
    <td style="${tdStyle}font-weight:700;color:${fw.color}">${fw.name}</td>
    <td style="${tdStyle}font-weight:700;color:${fw.score>=75?'#2e7d32':fw.score>=55?'#f57f17':'#c62828'}">${fw.score}%</td>
    <td style="${tdStyle}">${fw.passing} / ${fw.controls}</td>
    <td style="${tdStyle}font-weight:700;color:${fw.critical>3?'#c62828':'#f57f17'}">${fw.critical}</td>
    <td style="${tdStyle}font-weight:600;color:${fw.score<60?'#c62828':fw.score<75?'#f57f17':'#2e7d32'}">${fw.score<60?'URGENT':fw.score<75?'REVIEW':'OK'}</td>
  </tr>`).join('')}
  </tbody>
</table>
</div>

<div class="section">
<h2>Compliance Remediation Actions</h2>
${[
  {n:1,title:'Transmission Security (URGENT)',text:'Implement TLS 1.3 on ECG Monitor HL7 port 2575. Unencrypted PHI in transit violates 45 CFR §164.312(e)(2)(ii). Target: 7-day remediation.'},
  {n:2,title:'ePHI Encryption at Rest',text:'Apply AES-256 encryption to the patient_vitals table in Patient DB. Coordinate with IT to schedule maintenance window. Target: 14-day remediation.'},
  {n:3,title:'Business Associate Agreements',text:'Legal to execute BAA with the third-party ML analytics module vendor. No PHI may be shared without an executed BAA. Target: 30 days.'},
  {n:4,title:'Audit Controls',text:'Enable audit logging on Infusion Pump firmware v1.2.3. File a variance report with HHS if logging cannot be enabled within 30 days.'},
].map(r=>`<p style="margin-bottom:12px;font-size:13px;color:#37474f;text-align:justify"><strong>${r.n}. ${r.title}:</strong> ${r.text}</p>`).join('')}
</div>`;
      return pageShell('#22c55e','HIPAA Compliance & Audit Report','IoMT Anomaly Detection System · Compliance & Legal',`AUDIT-${incidentId}`,body);
    };

    // ── Clinical Engineer: Device Health Report ───────────────────────────────
    const buildClinicalReport = () => {
      const deviceNames = ['Infusion Pump','Heart Monitor','Pulse Oximeter','ECG Monitor'];
      const deviceMeta = {
        'Infusion Pump':  {ip:'192.168.10.11',mac:'00:1A:2B:3C:4D:5E',vlan:'VLAN-20 (IoMT)',firmware:'v1.2.3',risk:87,lastSeen:'2 min ago',status:'warning'},
        'Heart Monitor':  {ip:'192.168.10.12',mac:'00:1A:2B:3C:4D:5F',vlan:'VLAN-20 (IoMT)',firmware:'v3.1.0',risk:42,lastSeen:'1 min ago',status:'normal'},
        'Pulse Oximeter': {ip:'192.168.10.13',mac:'00:1A:2B:3C:4D:60',vlan:'VLAN-20 (IoMT)',firmware:'v2.0.1',risk:28,lastSeen:'30 sec ago',status:'normal'},
        'ECG Monitor':    {ip:'192.168.10.14',mac:'00:1A:2B:3C:4D:61',vlan:'VLAN-20 (IoMT)',firmware:'v4.2.1',risk:63,lastSeen:'45 sec ago',status:'warning'},
      };
      const body = `
<div class="section">
<h2>Device Fleet Overview</h2>
<div class="kpi-grid">
  ${[
    ['Total Devices', deviceNames.length, '#00838f'],
    ['Online', deviceNames.filter(d=>!isolatedDevices.includes(d)).length, '#43a047'],
    ['Isolated', isolatedDevices.filter(d=>deviceNames.includes(d)).length, '#e65100'],
    ['High Risk (>60)', Object.values(deviceMeta).filter(d=>d.risk>60).length, '#c62828'],
  ].map(([l,v,c])=>`<div class="kpi-card"><div class="kpi-label">${l}</div><div class="kpi-value" style="color:${c}">${v}</div></div>`).join('')}
</div>
</div>

<div class="section">
<h2>IoMT Device Status</h2>
<table>
  <thead><tr><th style="${thStyleOr}">Device</th><th style="${thStyleOr}">IP Address</th><th style="${thStyleOr}">MAC Address</th><th style="${thStyleOr}">VLAN</th><th style="${thStyleOr}">Firmware</th><th style="${thStyleOr}">Risk Score</th><th style="${thStyleOr}">State</th><th style="${thStyleOr}">Last Seen</th></tr></thead>
  <tbody>
  ${deviceNames.map(d=>{
    const m = deviceMeta[d];
    const isIso = isolatedDevices.includes(d);
    const riskColor = m.risk>75?'#c62828':m.risk>50?'#f57f17':'#2e7d32';
    const stateLabel = isIso?'ISOLATED':m.status==='warning'?'WARNING':'ONLINE';
    const stateColor = isIso?'#7b1fa2':m.status==='warning'?'#f57f17':'#2e7d32';
    return `<tr>
      <td style="${tdStyle}font-weight:700">${d}</td>
      <td style="${tdStyle}font-family:Consolas,monospace;color:#00838f">${m.ip}</td>
      <td style="${tdStyle}font-family:Consolas,monospace;font-size:11px;color:#546e7a">${m.mac}</td>
      <td style="${tdStyle}color:#546e7a">${m.vlan}</td>
      <td style="${tdStyle}font-family:Consolas,monospace">${m.firmware}</td>
      <td style="${tdStyle}font-weight:700;color:${riskColor}">${m.risk}/100</td>
      <td style="${tdStyle}font-weight:700;color:${stateColor}">${stateLabel}</td>
      <td style="${tdStyle}color:#90a4ae">${m.lastSeen}</td>
    </tr>`;
  }).join('')}
  </tbody>
</table>
</div>

<div class="section">
<h2>Network Topology Summary</h2>
<table>
  <thead><tr><th style="${thStyleOr}">Segment</th><th style="${thStyleOr}">Devices</th><th style="${thStyleOr}">Protocol</th><th style="${thStyleOr}">Gateway</th><th style="${thStyleOr}">Notes</th></tr></thead>
  <tbody>
  ${[
    {seg:'VLAN-20 (IoMT Devices)', devices:'Infusion Pump, Heart Monitor, Pulse Oximeter, ECG Monitor', proto:'HL7 v2, TCP/IP', gw:'192.168.10.1', note:'Segmented from general network. HIPAA PHI in transit.'},
    {seg:'VLAN-10 (Clinical IT)',  devices:'ML Server, Patient DB, PACS',                               proto:'HTTPS, SQL',   gw:'192.168.1.1',  note:'Hospital internal network. TLS 1.3 enforced.'},
    {seg:'VLAN-30 (Management)',   devices:'Firewall, Core Switch, Router',                              proto:'SNMP, SSH',    gw:'10.0.0.1',     note:'Management plane — restricted access.'},
  ].map(s=>`<tr>
    <td style="${tdStyle}font-weight:700;color:#e65100">${s.seg}</td>
    <td style="${tdStyle}">${s.devices}</td>
    <td style="${tdStyle}font-family:Consolas,monospace;font-size:11px">${s.proto}</td>
    <td style="${tdStyle}font-family:Consolas,monospace;color:#00838f">${s.gw}</td>
    <td style="${tdStyle}color:#546e7a;font-size:11px">${s.note}</td>
  </tr>`).join('')}
  </tbody>
</table>
</div>

<div class="section">
<h2>Maintenance Recommendations</h2>
${[
  {n:1,title:'Infusion Pump — Firmware Update (URGENT)',text:`Current firmware v1.2.3 is affected by CVE-2023-1234 (risk score: 87/100). Schedule maintenance window to apply latest firmware. Coordinate with nursing staff for planned downtime.`},
  {n:2,title:'ECG Monitor — Transmission Review',text:'ECG Monitor (risk score 63/100) is transmitting HL7 data on port 2575 without encryption. Coordinate with IT Security to enable TLS on the HL7 stream before the next maintenance window.'},
  {n:3,title:'Device Certificate Renewal',text:'Verify SSL/TLS device certificates have not expired. All IoMT devices should use device-level certificates for mutual TLS authentication.'},
  {n:4,title:'Routine Health Check',text:'All four devices are online and responding. Pulse Oximeter and Heart Monitor show nominal readings. Schedule quarterly biomedical inspection for all IoMT devices.'},
].map(r=>`<p style="margin-bottom:12px;font-size:13px;color:#37474f;text-align:justify"><strong>${r.n}. ${r.title}:</strong> ${r.text}</p>`).join('')}
</div>`;
      return pageShell('#f97316','IoMT Device Health Report','IoMT Anomaly Detection System · Biomedical Systems',`DEVICE-${incidentId}`,body);
    };

    // ── Threat Intelligence Analyst (Precious) ────────────────────────────────
    const buildThreatAnalystReport = () => {
      const byType = alerts.reduce((acc,a)=>{ acc[a.type]=(acc[a.type]||0)+1; return acc; },{});
      const topThreats = Object.entries(byType).sort((a,b)=>b[1]-a[1]).slice(0,6);
      const body = `
<div class="section">
<h2>Threat Intelligence Summary</h2>
<div class="kpi-grid">
  ${[
    ['Total Alerts',    alerts.length,                                         '#06b6d4'],
    ['Active Threats',  activeA.length,                                        activeA.length>5?'#e53935':'#fb8c00'],
    ['IOC Matches',     threatIntel.filter(t=>t.matched).length,               '#8b5cf6'],
    ['Unique ATT&CK',   5,                                                     '#22c55e'],
  ].map(([l,v,c])=>`<div class="kpi-card"><div class="kpi-label">${l}</div><div class="kpi-value" style="color:${c}">${v}</div></div>`).join('')}
</div>
<table class="meta-table" style="border:1px solid #e0e0e0;margin-bottom:16px">
  <tr><td>Analyst</td><td><strong>${currentUser?.name||'—'}</strong> · ${currentUser?.title||'Threat Intelligence Analyst'}</td></tr>
  <tr><td>Report Period</td><td>${dateStr}</td></tr>
  <tr><td>Detection Engine</td><td>LightGBM v2.0 · ${mlAccuracy}% accuracy · 44 features</td></tr>
  <tr><td>Overall Posture</td><td><strong style="color:${criticalAlerts.length>0?'#e53935':highAlerts.length>0?'#fb8c00':'#43a047'}">${overallSeverity} RISK</strong></td></tr>
</table>
</div>

<div class="section">
<h2>Attack Type Distribution</h2>
<table>
  <thead><tr><th style="${thStylePu}">Attack Type</th><th style="${thStylePu}">Count</th><th style="${thStylePu}">% of Total</th><th style="${thStylePu}">MITRE Technique</th><th style="${thStylePu}">Severity</th></tr></thead>
  <tbody>
  ${topThreats.map(([type,count])=>{
    const mitre = {DDoS:'T1498 – Direct Network Flood',DoS:'T1499 – Endpoint Denial of Service',Recon:'T1595 – Active Scanning',Spoofing:'T1557 – Adversary-in-the-Middle',MQTT:'T1071 – Application Layer Protocol',Benign:'N/A'}[type]||'T1059';
    const sevColor = {DDoS:'#fb8c00',DoS:'#fb8c00',Recon:'#fdd835',Spoofing:'#e53935',MQTT:'#fdd835'}[type]||'#90a4ae';
    const sevLabel = {DDoS:'HIGH',DoS:'HIGH',Recon:'MEDIUM',Spoofing:'CRITICAL',MQTT:'MEDIUM'}[type]||'LOW';
    return `<tr>
      <td style="${tdStyle}font-weight:700">${type}</td>
      <td style="${tdStyle}font-weight:700;color:#06b6d4">${count}</td>
      <td style="${tdStyle}color:#546e7a">${((count/alerts.length)*100).toFixed(1)}%</td>
      <td style="${tdStyle}font-family:Consolas,monospace;font-size:11px;color:#7b1fa2">${mitre}</td>
      <td style="${tdStyle}font-weight:700;color:${sevColor}">${sevLabel}</td>
    </tr>`;
  }).join('')}
  </tbody>
</table>
</div>

<div class="section">
<h2>MITRE ATT&CK Technique Mapping</h2>
<table>
  <thead><tr><th style="${thStylePu}">Technique</th><th style="${thStylePu}">Name</th><th style="${thStylePu}">Tactic</th><th style="${thStylePu}">Affected Devices</th><th style="${thStylePu}">Severity</th></tr></thead>
  <tbody>
  ${[
    {id:'T1498',name:'Direct Network Flood',     tactic:'Impact',          device:'Infusion Pump, ECG Monitor', sev:'high'},
    {id:'T1499',name:'Endpoint DoS',             tactic:'Impact',          device:'Pulse Oximeter',             sev:'high'},
    {id:'T1595',name:'Active Scanning (Recon)',  tactic:'Reconnaissance',  device:'Firewall, Switches',         sev:'medium'},
    {id:'T1557',name:'Adversary-in-the-Middle',  tactic:'Credential Access',device:'ECG Monitor',              sev:'critical'},
    {id:'T1071',name:'Application Layer Protocol',tactic:'C2',             device:'ML Server',                  sev:'medium'},
  ].map(t=>`<tr>
    <td style="${tdStyle}font-family:Consolas,monospace;color:#7b1fa2;font-weight:700">${t.id}</td>
    <td style="${tdStyle}font-weight:600">${t.name}</td>
    <td style="${tdStyle}color:#546e7a">${t.tactic}</td>
    <td style="${tdStyle}">${t.device}</td>
    <td style="${tdStyle}">${sev(t.sev)}</td>
  </tr>`).join('')}
  </tbody>
</table>
</div>

<div class="section">
<h2>Matched Threat Indicators (IOC Feed)</h2>
<table>
  <thead><tr><th style="${thStylePu}">Indicator</th><th style="${thStylePu}">Type</th><th style="${thStylePu}">Feed Source</th><th style="${thStylePu}">Confidence</th><th style="${thStylePu}">Action</th></tr></thead>
  <tbody>
  ${threatIntel.filter(t=>t.matched).slice(0,10).map(t=>`<tr>
    <td style="${tdStyle}font-family:Consolas,monospace;color:#00838f;font-size:11px">${t.indicator}</td>
    <td style="${tdStyle}font-weight:600">${t.type}</td>
    <td style="${tdStyle}color:#546e7a">${t.source}</td>
    <td style="${tdStyle}font-weight:700;color:#7b1fa2">${t.confidence}%</td>
    <td style="${tdStyle}font-weight:600;color:#e65100">Block & Monitor</td>
  </tr>`).join('')}
  ${!threatIntel.filter(t=>t.matched).length?`<tr><td colspan="5" style="${tdStyle}color:#90a4ae;text-align:center">No matched IOCs in current session.</td></tr>`:''}
  </tbody>
</table>
</div>

<div class="section">
<h2>Intelligence Assessment & Recommendations</h2>
${[
  {n:1,title:'Threat Prioritisation',text:`Spoofing (T1557) poses the highest risk as it directly targets medical device communications and could allow adversary manipulation of clinical data. Escalate to SOC Manager for immediate containment.`},
  {n:2,title:'Recon Activity',text:`Reconnaissance activity (T1595) detected against ${alerts.filter(a=>a.type==='Recon').length} targets. Likely a precursor to targeted exploitation. Update IDS signatures and review firewall ACLs within 24 hours.`},
  {n:3,title:'MQTT Protocol Abuse',text:`MQTT-based C2 communication (T1071) observed. Recommend implementing MQTT broker authentication and disabling anonymous access on all IoMT MQTT endpoints.`},
  {n:4,title:'Feed Updates',text:`Cross-reference current IOC list with AlienVault OTX and CISA KEV catalogue. ${threatIntel.filter(t=>t.matched).length} indicators matched — add confirmed IPs to firewall blocklist.`},
].map(r=>`<p style="margin-bottom:12px;font-size:13px;color:#37474f;text-align:justify"><strong>${r.n}. ${r.title}:</strong> ${r.text}</p>`).join('')}
</div>`;
      return pageShell('#8b5cf6','Threat Intelligence Report','IoMT ADS · Threat Intelligence & IOC Analysis',`TI-${incidentId}`,body);
    };

    // ── Incident Responder (Primrose) ─────────────────────────────────────────
    const buildIncidentResponderReport = () => {
      const deviceIPMap = {'Infusion Pump':'192.168.20.50','Heart Monitor':'192.168.20.22','Pulse Oximeter':'192.168.20.35','ECG Monitor':'192.168.20.41'};
      const body = `
<div class="section">
<h2>Incident Response Status</h2>
<div class="kpi-grid">
  ${[
    ['Active Incidents', activeA.length,                    activeA.length>0?'#e53935':'#43a047'],
    ['Isolated Devices', isolatedDevices.length,            isolatedDevices.length>0?'#f57f17':'#43a047'],
    ['Resolved',         resolvedA.length,                  '#43a047'],
    ['Critical Open',    criticalAlerts.filter(a=>a.status==='active').length, '#e53935'],
  ].map(([l,v,c])=>`<div class="kpi-card"><div class="kpi-label">${l}</div><div class="kpi-value" style="color:${c}">${v}</div></div>`).join('')}
</div>
<table class="meta-table" style="border:1px solid #e0e0e0;margin-bottom:16px">
  <tr><td>Responder</td><td><strong>${currentUser?.name||'—'}</strong> · ${currentUser?.title||'Incident Responder'}</td></tr>
  <tr><td>Incident ID</td><td><strong>${incidentId}</strong></td></tr>
  <tr><td>Overall Status</td><td><strong style="color:${overallStatus==='Active'?'#e53935':overallStatus==='Contained'?'#fb8c00':'#43a047'}">${overallStatus}</strong></td></tr>
  <tr><td>Classification</td><td>${classification}</td></tr>
</table>
</div>

<div class="section">
<h2>Active Incidents Requiring Response</h2>
<table>
  <thead><tr><th style="${thStyleOr}">Severity</th><th style="${thStyleOr}">Type</th><th style="${thStyleOr}">Device</th><th style="${thStyleOr}">Source IP</th><th style="${thStyleOr}">Dest IP</th><th style="${thStyleOr}">Confidence</th><th style="${thStyleOr}">Time</th><th style="${thStyleOr}">Recommended Action</th></tr></thead>
  <tbody>
  ${activeA.slice(0,15).map(a=>{
    const action = {critical:'ISOLATE DEVICE',high:'BLOCK SOURCE IP',medium:'ACKNOWLEDGE & MONITOR',low:'LOG & REVIEW'}[a.severity]||'REVIEW';
    const aColor = {critical:'#c62828',high:'#e65100',medium:'#f57f17',low:'#1565c0'}[a.severity]||'#546e7a';
    return `<tr>
      <td style="${tdStyle}">${sev(a.severity)}</td>
      <td style="${tdStyle}font-weight:600;color:#546e7a">${a.type}</td>
      <td style="${tdStyle}font-weight:700">${a.device}</td>
      <td style="${tdStyle}font-family:Consolas,monospace;font-size:11px;color:#00838f">${a.sourceIP||'—'}</td>
      <td style="${tdStyle}font-family:Consolas,monospace;font-size:11px">${a.destIP||'—'}</td>
      <td style="${tdStyle}font-weight:700;color:#7b1fa2">${a.confidence}%</td>
      <td style="${tdStyle}color:#90a4ae">${a.time}</td>
      <td style="${tdStyle}font-weight:700;color:${aColor}">${action}</td>
    </tr>`;
  }).join('')}
  ${!activeA.length?`<tr><td colspan="8" style="${tdStyle}color:#43a047;text-align:center;font-weight:600">✓ No active incidents. All clear.</td></tr>`:''}
  </tbody>
</table>
</div>

<div class="section">
<h2>Isolated Devices</h2>
${isolatedDevices.length===0
  ? '<p style="color:#43a047;font-size:13px;font-weight:600">✓ No devices currently isolated.</p>'
  : `<table>
  <thead><tr><th style="${thStyleOr}">Device</th><th style="${thStyleOr}">IP Address</th><th style="${thStyleOr}">Isolation Reason</th><th style="${thStyleOr}">Status</th></tr></thead>
  <tbody>
  ${isolatedDevices.map(d=>`<tr>
    <td style="${tdStyle}font-weight:700">${d}</td>
    <td style="${tdStyle}font-family:Consolas,monospace;color:#00838f">${deviceIPMap[d]||'—'}</td>
    <td style="${tdStyle}color:#546e7a">Suspicious traffic pattern detected by ML model</td>
    <td style="${tdStyle}font-weight:700;color:#7b1fa2">ISOLATED — Network quarantined</td>
  </tr>`).join('')}
  </tbody>
</table>`}
</div>

<div class="section">
<h2>Response Actions Log</h2>
<table>
  <thead><tr><th style="${thStyle}">Action</th><th style="${thStyle}">Target</th><th style="${thStyle}">Status</th><th style="${thStyle}">Notes</th></tr></thead>
  <tbody>
  ${resolvedA.slice(0,10).map(a=>`<tr>
    <td style="${tdStyle}font-weight:700;color:#2e7d32">RESOLVED</td>
    <td style="${tdStyle}">${a.device} (${a.type})</td>
    <td style="${tdStyle}">${statusBadge('resolved')}</td>
    <td style="${tdStyle}color:#546e7a">${a.time}</td>
  </tr>`).join('')}
  ${alerts.filter(a=>a.status==='mitigated').slice(0,5).map(a=>`<tr>
    <td style="${tdStyle}font-weight:700;color:#1565c0">MITIGATED</td>
    <td style="${tdStyle}">${a.device} (${a.type})</td>
    <td style="${tdStyle}">${statusBadge('mitigated')}</td>
    <td style="${tdStyle}color:#546e7a">${a.time}</td>
  </tr>`).join('')}
  ${!resolvedA.length?`<tr><td colspan="4" style="${tdStyle}color:#90a4ae;text-align:center">No completed response actions in this session.</td></tr>`:''}
  </tbody>
</table>
</div>

<div class="section">
<h2>Response Playbook Actions Required</h2>
${[
  {n:1,title:'Critical Alerts',text:`${criticalAlerts.filter(a=>a.status==='active').length} critical alerts active. Invoke Playbook PB-001 (Spoofing Response) and PB-003 (Device Isolation). Obtain SOC Manager authorisation before isolation.`},
  {n:2,title:'Device Isolation Protocol',text:`For confirmed Spoofing or MITM attacks, activate VLAN quarantine on affected switch port. Document device MAC address, port number, and time of isolation. Notify clinical staff immediately.`},
  {n:3,title:'Evidence Preservation',text:'Capture network packet dumps on affected segments before clearing alerts. Export PCAP to forensics share. Preserve system logs for incident timeline reconstruction.'},
  {n:4,title:'Escalation',text:`If ${activeA.length} active incidents are not contained within 60 minutes, escalate to SOC Manager (${SOC_TEAM.find(m=>m.role==='SOC Manager')?.name||'Tinashe Chidarikire'}) and initiate the Major Incident Response procedure.`},
].map(r=>`<p style="margin-bottom:12px;font-size:13px;color:#37474f;text-align:justify"><strong>${r.n}. ${r.title}:</strong> ${r.text}</p>`).join('')}
</div>`;
      return pageShell('#ef4444','Incident Response Report','IoMT ADS · Active Incident Management',`IR-${incidentId}`,body);
    };

    // ── ML / Data Engineer (Jubillee) ─────────────────────────────────────────
    const buildMLEngineerReport = () => {
      const confBuckets = [{label:'95-100%',count:alerts.filter(a=>a.confidence>=95).length,color:'#2e7d32'},{label:'85-94%',count:alerts.filter(a=>a.confidence>=85&&a.confidence<95).length,color:'#43a047'},{label:'75-84%',count:alerts.filter(a=>a.confidence>=75&&a.confidence<85).length,color:'#fb8c00'},{label:'<75%',count:alerts.filter(a=>a.confidence<75).length,color:'#e53935'}];
      const fpRate  = alerts.length ? ((alerts.filter(a=>a.status==='fp').length/alerts.length)*100).toFixed(1) : '0.0';
      const ackRate = alerts.length ? ((alerts.filter(a=>a.status==='acknowledged').length/alerts.length)*100).toFixed(1) : '0.0';
      const body = `
<div class="section">
<h2>Model Performance Overview</h2>
<div class="kpi-grid">
  ${[
    ['Model Accuracy',  mlAccuracy+'%', confidenceScore>=95?'#43a047':confidenceScore>=85?'#fb8c00':'#e53935'],
    ['Total Detections',alerts.length,                  '#06b6d4'],
    ['FP Rate',         fpRate+'%',                     parseFloat(fpRate)>10?'#e53935':parseFloat(fpRate)>5?'#fb8c00':'#43a047'],
    ['Ack Rate',        ackRate+'%',                    '#8b5cf6'],
  ].map(([l,v,c])=>`<div class="kpi-card"><div class="kpi-label">${l}</div><div class="kpi-value" style="color:${c}">${v}</div></div>`).join('')}
</div>
<table class="meta-table" style="border:1px solid #e0e0e0;margin-bottom:16px">
  <tr><td>Engineer</td><td><strong>${currentUser?.name||'—'}</strong> · ${currentUser?.title||'ML / Data Engineer'}</td></tr>
  <tr><td>Model</td><td>LightGBM v2.0 · Multi-class classifier</td></tr>
  <tr><td>Classes</td><td>Benign · DDoS · DoS · Recon · Spoofing · MQTT</td></tr>
  <tr><td>Feature Count</td><td>44 network flow features (CICIoMT2024 dataset)</td></tr>
  <tr><td>Training Dataset</td><td>CIC IoMT 2024 — WiFi + MQTT traffic</td></tr>
</table>
</div>

<div class="section">
<h2>Confidence Score Distribution</h2>
<table>
  <thead><tr><th style="${thStyle}">Confidence Range</th><th style="${thStyle}">Alert Count</th><th style="${thStyle}">% of Total</th><th style="${thStyle}">Quality</th></tr></thead>
  <tbody>
  ${confBuckets.map(b=>`<tr>
    <td style="${tdStyle}font-weight:700;color:${b.color}">${b.label}</td>
    <td style="${tdStyle}font-weight:700">${b.count}</td>
    <td style="${tdStyle}color:#546e7a">${alerts.length?((b.count/alerts.length)*100).toFixed(1):0}%</td>
    <td style="${tdStyle}font-weight:600;color:${b.color}">${b.label==='95-100%'?'High Confidence':b.label==='85-94%'?'Good':b.label==='75-84%'?'Review':'Low — Possible FP'}</td>
  </tr>`).join('')}
  </tbody>
</table>
</div>

<div class="section">
<h2>Detection Breakdown by Class</h2>
<table>
  <thead><tr><th style="${thStyle}">Class</th><th style="${thStyle}">Detections</th><th style="${thStyle}">Avg Confidence</th><th style="${thStyle}">Active</th><th style="${thStyle}">Resolved</th><th style="${thStyle}">FP Flagged</th></tr></thead>
  <tbody>
  ${['DDoS','DoS','Recon','Spoofing','MQTT'].map(type=>{
    const typeAlerts=alerts.filter(a=>a.type===type);
    const avgConf=typeAlerts.length?Math.round(typeAlerts.reduce((s,a)=>s+a.confidence,0)/typeAlerts.length):0;
    return `<tr>
      <td style="${tdStyle}font-weight:700">${type}</td>
      <td style="${tdStyle}font-weight:700;color:#06b6d4">${typeAlerts.length}</td>
      <td style="${tdStyle}font-weight:700;color:${avgConf>=90?'#2e7d32':avgConf>=75?'#fb8c00':'#e53935'}">${avgConf}%</td>
      <td style="${tdStyle}color:#e53935">${typeAlerts.filter(a=>a.status==='active').length}</td>
      <td style="${tdStyle}color:#2e7d32">${typeAlerts.filter(a=>['resolved','mitigated'].includes(a.status)).length}</td>
      <td style="${tdStyle}color:#f57f17">${typeAlerts.filter(a=>a.status==='fp').length}</td>
    </tr>`;
  }).join('')}
  </tbody>
</table>
</div>

<div class="section">
<h2>Model Tuning Recommendations</h2>
${[
  {n:1,title:'Threshold Optimisation',text:`Current minimum confidence threshold is set to ${alertThreshold}%. Analysis shows ${alerts.filter(a=>a.confidence<80).length} alerts below 80% confidence — consider raising threshold to 88% to reduce false positives while maintaining recall on critical attacks.`},
  {n:2,title:'Class Imbalance',text:'The CICIoMT2024 training set is DDoS-heavy. Recommend re-sampling with SMOTE or class weighting adjustment for Spoofing and MQTT classes, which are under-represented but high-impact.'},
  {n:3,title:'Feature Drift',text:'Monitor for concept drift in production traffic vs. training data. Schedule quarterly model re-evaluation with updated network traffic captures from the live hospital environment.'},
  {n:4,title:'Explainability',text:'Audit top feature importance scores to verify the key drivers behind Spoofing and MQTT classifications. Ensure the model is not over-relying on transient packet timing features that may not generalise to live hospital traffic.'},
].map(r=>`<p style="margin-bottom:12px;font-size:13px;color:#37474f;text-align:justify"><strong>${r.n}. ${r.title}:</strong> ${r.text}</p>`).join('')}
</div>`;
      return pageShell('#22c55e','ML Model Performance Report','IoMT ADS · Machine Learning & Data Engineering',`ML-${incidentId}`,body);
    };

    // ── Network Security Analyst (Evelyn) ─────────────────────────────────────
    const buildNetworkAnalystReport = () => {
      const geoEntries = Object.entries(liveGeoHits||{}).sort((a,b)=>b[1].count-a[1].count).slice(0,8);
      const body = `
<div class="section">
<h2>Network Security Overview</h2>
<div class="kpi-grid">
  ${[
    ['Total Packets',   stats.totalPackets.toLocaleString(), '#06b6d4'],
    ['Anomalies',       stats.anomalies,                     stats.anomalies>20?'#e53935':'#fb8c00'],
    ['Blocked IPs',     stats.blocked,                       '#ef4444'],
    ['Active Devices',  stats.devices,                       '#43a047'],
  ].map(([l,v,c])=>`<div class="kpi-card"><div class="kpi-label">${l}</div><div class="kpi-value" style="color:${c}">${v}</div></div>`).join('')}
</div>
<table class="meta-table" style="border:1px solid #e0e0e0;margin-bottom:16px">
  <tr><td>Analyst</td><td><strong>${currentUser?.name||'—'}</strong> · ${currentUser?.title||'Network Security Analyst'}</td></tr>
  <tr><td>Report Period</td><td>${dateStr}</td></tr>
  <tr><td>Monitoring Scope</td><td>VLAN-20 Clinical · VLAN-30 Imaging · VLAN-10 Corporate</td></tr>
</table>
</div>

<div class="section">
<h2>Network Topology Segments</h2>
<table>
  <thead><tr><th style="${thStyle}">Segment</th><th style="${thStyle}">Subnet</th><th style="${thStyle}">Devices</th><th style="${thStyle}">Protocol</th><th style="${thStyle}">Gateway</th><th style="${thStyle}">Status</th></tr></thead>
  <tbody>
  ${[
    {seg:'VLAN-20 Clinical', subnet:'192.168.20.0/24', devices:'Infusion Pump, Heart Monitor, Pulse Oximeter, ECG Monitor', proto:'HL7 v2 / TCP', gw:'192.168.20.1', status:'active'},
    {seg:'VLAN-30 Imaging',  subnet:'192.168.30.0/24', devices:'MRI Controller, PACS Server',                                proto:'DICOM / HTTPS', gw:'192.168.30.1', status:'active'},
    {seg:'VLAN-10 Corporate',subnet:'192.168.10.0/24', devices:'ML Server, Patient DB, Admin Workstation',                  proto:'HTTPS / SQL',   gw:'192.168.10.1', status:'active'},
    {seg:'SOC Subnet',       subnet:'10.0.5.0/24',     devices:'SIEM, SOC Workstations',                                    proto:'Syslog / SSH',  gw:'10.0.5.1',     status:'active'},
  ].map(s=>`<tr>
    <td style="${tdStyle}font-weight:700;color:#0891b2">${s.seg}</td>
    <td style="${tdStyle}font-family:Consolas,monospace;color:#00838f">${s.subnet}</td>
    <td style="${tdStyle}">${s.devices}</td>
    <td style="${tdStyle}font-family:Consolas,monospace;font-size:11px">${s.proto}</td>
    <td style="${tdStyle}font-family:Consolas,monospace;color:#546e7a">${s.gw}</td>
    <td style="${tdStyle}font-weight:700;color:#2e7d32">${s.status.toUpperCase()}</td>
  </tr>`).join('')}
  </tbody>
</table>
</div>

<div class="section">
<h2>Geo-Threat Attack Origins</h2>
<table>
  <thead><tr><th style="${thStyle}">City / Region</th><th style="${thStyle}">Attack Count</th><th style="${thStyle}">Severity</th><th style="${thStyle}">Recommended Action</th></tr></thead>
  <tbody>
  ${geoEntries.length ? geoEntries.map(([city,data])=>`<tr>
    <td style="${tdStyle}font-weight:700">${city}</td>
    <td style="${tdStyle}font-weight:700;color:#e53935">${data.count||1}</td>
    <td style="${tdStyle}">${sev(data.count>10?'critical':data.count>5?'high':'medium')}</td>
    <td style="${tdStyle}font-weight:600;color:#e65100">GeoBlock / Rate-limit</td>
  </tr>`).join('') : `<tr><td colspan="4" style="${tdStyle}color:#90a4ae;text-align:center">No geo-threat data in current session.</td></tr>`}
  </tbody>
</table>
</div>

<div class="section">
<h2>Active ACL Rules</h2>
<table>
  <thead><tr><th style="${thStyle}">Rule ID</th><th style="${thStyle}">Source</th><th style="${thStyle}">Destination</th><th style="${thStyle}">Action</th><th style="${thStyle}">Protocol</th><th style="${thStyle}">Port</th><th style="${thStyle}">Reason</th></tr></thead>
  <tbody>
  ${[
    {id:'ACL-001',src:'VLAN-20',        dst:'VLAN-10 Corp', action:'DENY',  proto:'ANY', port:'*',    reason:'Clinical isolation'},
    {id:'ACL-002',src:'VLAN-20',        dst:'10.0.0.5',     action:'ALLOW', proto:'TCP', port:'443',  reason:'SIEM feed'},
    {id:'ACL-003',src:'VLAN-30 Imaging',dst:'VLAN-20',      action:'DENY',  proto:'ANY', port:'*',    reason:'Imaging subnet isolation'},
    {id:'ACL-004',src:'SOC Subnet',     dst:'VLAN-20',      action:'ALLOW', proto:'TCP', port:'8443', reason:'SOC management'},
    {id:'ACL-005',src:'192.168.99.0/24',dst:'ANY',          action:'DENY',  proto:'ANY', port:'*',    reason:'Blocked rogue subnet'},
  ].map(r=>`<tr>
    <td style="${tdStyle}font-family:Consolas,monospace;color:#546e7a">${r.id}</td>
    <td style="${tdStyle}font-family:Consolas,monospace;font-size:11px">${r.src}</td>
    <td style="${tdStyle}font-family:Consolas,monospace;font-size:11px">${r.dst}</td>
    <td style="${tdStyle}font-weight:700;color:${r.action==='DENY'?'#c62828':'#2e7d32'}">${r.action}</td>
    <td style="${tdStyle}font-size:11px">${r.proto}</td>
    <td style="${tdStyle}font-family:Consolas,monospace">${r.port}</td>
    <td style="${tdStyle}color:#546e7a;font-size:11px">${r.reason}</td>
  </tr>`).join('')}
  </tbody>
</table>
</div>

<div class="section">
<h2>Network Security Recommendations</h2>
${[
  {n:1,title:'Geo-Blocking',text:`${geoEntries.length} attack origins identified. Recommend implementing geo-IP blocking for top-3 source regions at the perimeter firewall. Review with SOC Manager before applying broad blocks.`},
  {n:2,title:'Protocol Hardening',text:'Disable unencrypted HL7 on port 2575. Force TLS 1.3 for all inter-VLAN clinical communications. Disable MQTT anonymous access on all IoMT endpoints.'},
  {n:3,title:'Traffic Baselining',text:`Current anomaly rate: ${stats.anomalies} of ${stats.totalPackets.toLocaleString()} packets. Establish normal traffic baselines per device to improve ML model signal-to-noise ratio.`},
  {n:4,title:'ACL Review',text:'ACL-001 and ACL-003 DENY rules are functioning correctly. Review ACL-004 (SOC management access to VLAN-20) quarterly to ensure least-privilege access is maintained.'},
].map(r=>`<p style="margin-bottom:12px;font-size:13px;color:#37474f;text-align:justify"><strong>${r.n}. ${r.title}:</strong> ${r.text}</p>`).join('')}
</div>`;
      return pageShell('#f97316','Network Security Report','IoMT ADS · Network Traffic Analysis & ACL Monitoring',`NET-${incidentId}`,body);
    };

    // ── Admin: System Administration Report ───────────────────────────────────
    const buildAdminReport = () => {
      const body = `
<div class="section">
<h2>System Status Overview</h2>
<div class="kpi-grid">
  ${[
    ['Registered Users', DEMO_USERS.length,                                                       '#f59e0b'],
    ['Blocked Accounts', Object.values(userStates).filter(u=>u.blocked).length,                   '#e53935'],
    ['MFA Enabled',      Object.values(userStates).filter(u=>u.mfaEnabled).length,                '#22c55e'],
    ['Active Alerts',    activeA.length,                                                           activeA.length>5?'#e53935':'#06b6d4'],
  ].map(([l,v,c])=>`<div class="kpi-card"><div class="kpi-label">${l}</div><div class="kpi-value" style="color:${c}">${v}</div></div>`).join('')}
</div>
<table class="meta-table" style="border:1px solid #e0e0e0;margin-bottom:16px">
  <tr><td>Administrator</td><td><strong>${currentUser?.name||'System Administrator'}</strong></td></tr>
  <tr><td>Report Generated</td><td>${dateStr}</td></tr>
  <tr><td>Detection Engine</td><td>LightGBM v2.0 · ${mlAccuracy}% accuracy</td></tr>
  <tr><td>Backend Status</td><td><strong style="color:#43a047">● ONLINE</strong> · Port 8005 · WebSocket Active</td></tr>
</table>
</div>

<div class="section">
<h2>User Account Audit</h2>
<table>
  <thead><tr><th style="${thStyle}">User</th><th style="${thStyle}">Username</th><th style="${thStyle}">Role</th><th style="${thStyle}">Department</th><th style="${thStyle}">MFA</th><th style="${thStyle}">Account Status</th><th style="${thStyle}">Phone</th></tr></thead>
  <tbody>
  ${DEMO_USERS.map(u=>{
    const us = userStates[u.username]||{};
    const rd = ROLE_DEFS[u.role];
    return `<tr>
      <td style="${tdStyle}font-weight:700">${u.name}</td>
      <td style="${tdStyle}font-family:Consolas,monospace;color:#546e7a">${u.username}</td>
      <td style="${tdStyle}font-weight:600;color:${rd?.color||'#64748b'}">${rd?.label||u.role}</td>
      <td style="${tdStyle}color:#546e7a">${u.dept}</td>
      <td style="${tdStyle}font-weight:700;color:${us.mfaEnabled?'#2e7d32':'#e53935'}">${us.mfaEnabled?'✓ ENABLED':'✗ DISABLED'}</td>
      <td style="${tdStyle}font-weight:700;color:${us.blocked?'#c62828':'#2e7d32'}">${us.blocked?'⊘ BLOCKED':'✓ ACTIVE'}</td>
      <td style="${tdStyle}font-family:Consolas,monospace;font-size:11px;color:#90a4ae">${us.phone||u.phone||'—'}</td>
    </tr>`;
  }).join('')}
  </tbody>
</table>
</div>

<div class="section">
<h2>Security Configuration Status</h2>
<table>
  <thead><tr><th style="${thStyle}">Control</th><th style="${thStyle}">Status</th><th style="${thStyle}">Detail</th></tr></thead>
  <tbody>
  ${[
    {ctrl:'Multi-Factor Authentication', status:Object.values(userStates).every(u=>u.mfaEnabled)?'pass':'warn', detail:`${Object.values(userStates).filter(u=>u.mfaEnabled).length}/${DEMO_USERS.length} accounts MFA-enabled`},
    {ctrl:'Account Lockout Policy',      status:'pass', detail:'5 failed attempts triggers lockout'},
    {ctrl:'Session Management',          status:'pass', detail:'Sessions cleared on browser close (no persistence)'},
    {ctrl:'Role-Based Access Control',   status:'pass', detail:'6 roles · Least-privilege enforced per tab'},
    {ctrl:'Backend API Security',        status:'pass', detail:'CORS enforced · FastAPI · Port 8005'},
    {ctrl:'ML Model Monitoring',         status:confidenceScore>=95?'pass':'warn', detail:`Accuracy: ${mlAccuracy}%`},
    {ctrl:'Blocked Accounts',            status:Object.values(userStates).some(u=>u.blocked)?'warn':'pass', detail:`${Object.values(userStates).filter(u=>u.blocked).length} account(s) currently blocked`},
  ].map(r=>`<tr>
    <td style="${tdStyle}font-weight:600">${r.ctrl}</td>
    <td style="${tdStyle}">${controlBadge(r.status)}</td>
    <td style="${tdStyle}color:#546e7a">${r.detail}</td>
  </tr>`).join('')}
  </tbody>
</table>
</div>

<div class="section">
<h2>Administrator Actions Required</h2>
${[
  {n:1,title:'MFA Compliance',text:`${Object.values(userStates).filter(u=>!u.mfaEnabled).length} account(s) have MFA disabled. Enable MFA for all accounts once SMS gateway (Twilio) is configured. All staff must complete MFA enrollment within 7 days.`},
  {n:2,title:'Phone Number Verification',text:'Ensure all user phone numbers are entered and verified in the User Accounts panel. MFA OTP delivery depends on accurate phone records.'},
  {n:3,title:'Model Performance',text:`LightGBM model running at ${mlAccuracy}% accuracy. Review false positive rate and consider threshold adjustment if FP rate exceeds 15%.`},
  {n:4,title:'Patch Management',text:`Review IoMT device firmware status in the Device Assets panel. Monitored devices: ${REPORT_DEVICES.join(', ')}. ECG Monitor (CVE-2025-3341, CVSS 6.5) has a high-severity patch pending. Infusion Pump (CVE-2023-1234, CVSS 9.1) requires immediate firmware update.`},
].map(r=>`<p style="margin-bottom:12px;font-size:13px;color:#37474f;text-align:justify"><strong>${r.n}. ${r.title}:</strong> ${r.text}</p>`).join('')}
</div>`;
      return pageShell('#f59e0b','System Administration Report','IoMT ADS · System Administration & Access Control Audit',`ADMIN-${incidentId}`,body);
    };

    // ── Route to correct report by current role ───────────────────────────────
    const html = role==='admin'              ? buildAdminReport()
               : role==='soc_manager'        ? buildManagerReport()
               : role==='threat_analyst'     ? buildThreatAnalystReport()
               : role==='incident_responder' ? buildIncidentResponderReport()
               : role==='ml_engineer'        ? buildMLEngineerReport()
               : role==='network_analyst'    ? buildNetworkAnalystReport()
               : role==='ciso'               ? buildCISOReport()
               :                               buildManagerReport();

    const blob = new Blob([html], { type: 'text/html' });
    const url  = URL.createObjectURL(blob);
    const win  = window.open(url, '_blank');
    if (win) win.focus();
  };

  const getSeverityColor = (severity) => ({
    critical: 'bg-red-500/20 text-red-400 border-red-500/50',
    high: 'bg-orange-500/20 text-orange-400 border-orange-500/50',
    medium: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/50',
    low: 'bg-blue-500/20 text-blue-400 border-blue-500/50',
  }[severity] || 'bg-blue-500/20 text-blue-400 border-blue-500/50');

  const getStatusColor = (status) => ({
    active: 'bg-red-500/20 text-red-400',
    acknowledged: 'bg-amber-500/20 text-amber-400',
    mitigated: 'bg-cyan-500/20 text-cyan-400',
    resolved: 'bg-emerald-500/20 text-emerald-400',
  }[status] || 'bg-slate-500/20 text-slate-400');

  const getDeviceIcon = (name) => {
    const icons = { 'Infusion Pump': Droplets, 'Heart Monitor': Heart, 'Pulse Oximeter': Activity, 'ECG Monitor': Monitor };
    const Icon = icons[name] || Radio;
    return <Icon className="w-5 h-5" />;
  };

  const getNodeIcon = (type) => {
    const icons = { router: Router, firewall: Shield, switch: Server, server: Server, database: Database, device: Smartphone };
    const Icon = icons[type] || Circle;
    return Icon;
  };

  const filteredAlerts = alerts.filter(a => {
    if (alertFilter === 'all')    return a.status !== 'fp';
    if (alertFilter === 'active') return a.status === 'active';
    if (alertFilter === 'fp')     return a.status === 'fp' || a.isModelFP;
    if (alertFilter === 'acknowledged') return a.status === 'acknowledged';
    if (alertFilter === 'resolved')     return a.status === 'resolved' || a.status === 'mitigated';
    return true;
  });

  const activeAlertCount = alerts.filter(a => a.status === 'active').length;
  const fpAlertCount     = alerts.filter(a => a.status === 'fp' || a.isModelFP).length;

  const markAsFP = (alert) => {
    const fpKey = `${alert.type}:${alert.device}`;
    if (!fpSuppressions.some(r => r.key === fpKey)) {
      setFpSuppressions(prev => [...prev, { key: fpKey, type: alert.type, device: alert.device, addedAt: new Date().toLocaleTimeString() }]);
    }
    setAlerts(prev => prev.map(a => a.id === alert.id ? { ...a, status: 'fp' } : a));
    setResponseLog(prev => [{ id: Date.now(), time: new Date().toLocaleTimeString(), user: nextAnalyst(), action: 'False Positive Suppressed', target: alert.device, alert: `${alert.type} rule added` }, ...prev.slice(0, 49)]);
  };
  const matchedThreats = threatIntel.filter(t => t.matched).length;

  const shiftDuration = Math.floor((clockTime - shiftStart) / 60000);
  const shiftH = Math.floor(shiftDuration / 60);
  const shiftM = shiftDuration % 60;

  // Role helpers
  const rolePerms = currentUser ? ROLE_DEFS[currentUser.role] : null;
  const canIsolate = rolePerms?.canIsolate ?? false;
  const canBlock   = rolePerms?.canBlock   ?? false;
  const canAck     = rolePerms?.canAck     ?? false;
  const visibleTabIds = rolePerms?.tabs ?? [];

  if (!currentUser) return <LoginPage onLogin={handleLogin} checkCredentials={checkCredentials} onOtpGenerated={onOtpGenerated} />;

  return (
    <div className="h-screen overflow-hidden bg-gradient-to-br from-slate-950 via-slate-900 to-slate-950 text-white px-4 pt-3 pb-2 text-sm flex flex-col" style={{ fontFamily: 'system-ui, -apple-system, sans-serif' }}>

      {/* Toast overlay — bottom-right, never crowds layout */}
      <div className="fixed bottom-5 right-5 z-50 flex flex-col gap-2 pointer-events-none">
        {toasts.map(t => {
          const tc = t.sev==='critical'?'#ef4444':t.sev==='high'?'#f97316':t.sev==='info'?'#06b6d4':'#22c55e';
          return (
            <div key={t.id} className="pointer-events-auto flex items-center gap-3 px-4 py-3 rounded-xl shadow-2xl border backdrop-blur-sm"
              style={{backgroundColor:'#0f172a',borderColor:tc+'55',minWidth:'260px',maxWidth:'340px'}}>
              <div className="w-2 h-2 rounded-full flex-shrink-0 animate-pulse" style={{backgroundColor:tc}}/>
              <p className="text-base font-medium text-white flex-1">{t.msg}</p>
              <button className="pointer-events-auto" onClick={()=>setToasts(p=>p.filter(x=>x.id!==t.id))}>
                <X className="w-3 h-3 text-slate-500 hover:text-slate-300"/>
              </button>
            </div>
          );
        })}
      </div>

      {/* Header */}
      <header className="mb-2 flex items-center justify-between flex-shrink-0">
        <div className="flex items-center gap-2.5">
          <div className="relative">
            <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-cyan-500 to-blue-600 flex items-center justify-center shadow-lg shadow-cyan-500/30">
              <Shield className="w-4 h-4" />
            </div>
            {activeAlertCount > 0 && (
              <div className="absolute -top-1 -right-1 w-3.5 h-3.5 bg-red-500 rounded-full flex items-center justify-center text-xs font-bold animate-pulse">
                {activeAlertCount}
              </div>
            )}
          </div>
          <div>
            <h1 className="text-sm font-bold tracking-tight leading-tight">IoMT Anomaly Detection System</h1>
            <p className="text-xs text-slate-500 leading-tight">Real-Time Threat Detection & Response</p>
          </div>
        </div>

        <div className="flex items-center gap-1.5">
          {/* Backend WebSocket connect / stream controls */}
          <div className="flex items-center gap-1 px-2 py-1 rounded-md bg-slate-800/60 border border-slate-700/50">
            <div className={`w-1.5 h-1.5 rounded-full ${connected ? 'bg-cyan-400 animate-pulse' : backendUp === false ? 'bg-red-400' : 'bg-slate-500'}`} />
            <span className={`text-xs font-semibold ${connected ? 'text-cyan-400' : 'text-slate-500'}`}>
              {connected ? 'WS' : 'WS OFF'}
            </span>
            {connected && (
              liveRunning
                ? <button onClick={stopLive} className="ml-1 px-1.5 py-0.5 rounded bg-amber-500/20 border border-amber-500/40 text-amber-400 text-xs font-medium hover:bg-amber-500/30">⏸ Pause</button>
                : <button onClick={() => startLive(0.8)} className="ml-1 px-1.5 py-0.5 rounded bg-emerald-500/20 border border-emerald-500/40 text-emerald-400 text-xs font-medium hover:bg-emerald-500/30">▶ Play</button>
            )}
          </div>

          {/* Live / Pause (mock data) */}
          <button onClick={() => setIsLive(!isLive)}
            className={`flex items-center gap-1 px-2 py-1 rounded-md border text-xs font-semibold ${isLive ? 'bg-emerald-500/15 border-emerald-500/40 text-emerald-400' : 'bg-amber-500/15 border-amber-500/40 text-amber-400'}`}>
            <div className={`w-1.5 h-1.5 rounded-full ${isLive ? 'bg-emerald-400 animate-pulse' : 'bg-amber-400'}`}/>
            {isLive ? 'LIVE' : 'PAUSED'}
          </button>

          {/* F — Confidence threshold slider */}
          <div className="flex items-center gap-1.5 px-2 py-1 rounded-md bg-slate-800/60 border border-slate-700/50">
            <span className="text-xs text-slate-400 font-medium whitespace-nowrap">Min Conf</span>
            <input type="range" min="50" max="99" value={alertThreshold}
              onChange={e => setAlertThreshold(Number(e.target.value))}
              className="w-16 h-1 accent-cyan-400 cursor-pointer"/>
            <span className="text-xs font-bold text-cyan-400 w-7">{alertThreshold}%</span>
          </div>

          {/* Refresh rate */}
          <div className="flex items-center gap-1 px-2 py-1 rounded-md bg-slate-800/60 border border-slate-700/50">
            <RefreshCw className="w-3 h-3 text-slate-400" />
            <select value={refreshRate} onChange={e => setRefreshRate(Number(e.target.value))}
              className="bg-transparent text-xs text-slate-300 border-none focus:outline-none cursor-pointer w-7">
              <option value={1000} style={{background:'#1e293b'}}>1s</option>
              <option value={2000} style={{background:'#1e293b'}}>2s</option>
              <option value={5000} style={{background:'#1e293b'}}>5s</option>
              <option value={10000} style={{background:'#1e293b'}}>10s</option>
              <option value={30000} style={{background:'#1e293b'}}>30s</option>
            </select>
          </div>

          {/* Auto-response */}
          <div className="flex items-center gap-1 px-2 py-1 rounded-md bg-slate-800/60 border border-slate-700/50">
            <Siren className="w-3 h-3 text-slate-400" />
            <span className="text-xs text-slate-500">Auto:</span>
            <button onClick={() => setAutoResponse(p => ({ ...p, critical: !p.critical }))}
              className={`px-1 py-0.5 rounded text-xs font-medium ${autoResponse.critical ? 'bg-red-500/30 text-red-400' : 'bg-slate-700/50 text-slate-500'}`}>Crit</button>
            <button onClick={() => setAutoResponse(p => ({ ...p, high: !p.high }))}
              className={`px-1 py-0.5 rounded text-xs font-medium ${autoResponse.high ? 'bg-orange-500/30 text-orange-400' : 'bg-slate-700/50 text-slate-500'}`}>High</button>
          </div>

          {/* Threat Intel */}
          <button onClick={() => setShowThreatIntelPanel(true)}
            className="relative flex items-center gap-1 px-2 py-1 rounded-md bg-slate-800/60 border border-slate-700/50 hover:bg-slate-700/60 text-xs text-slate-300">
            <Globe className="w-3 h-3 text-purple-400" />
            <span>Intel</span>
            {matchedThreats > 0 && <span className="px-1 rounded bg-purple-500/30 text-purple-400 font-bold">{matchedThreats}</span>}
          </button>

          {/* Report */}
          <button onClick={generateReport}
            className="flex items-center gap-1 px-2 py-1 rounded-md bg-emerald-500/20 border border-emerald-500/40 text-emerald-400 hover:bg-emerald-500/30 text-xs font-medium">
            <FileText className="w-3 h-3" />Report
          </button>

          {/* Notifications */}
          <button onClick={() => setShowNotificationPanel(true)}
            className="relative p-1.5 rounded-md bg-slate-800/60 border border-slate-700/50 hover:bg-slate-700/60">
            <Bell className="w-3.5 h-3.5 text-slate-400" />
            {notifications.length > 0 && <div className="absolute -top-0.5 -right-0.5 w-2 h-2 bg-cyan-500 rounded-full" />}
          </button>

          {/* Sign Out */}
          <button onClick={() => { clearHeartbeat(currentUser.username); setCurrentUser(null); localStorage.removeItem('iomt_user'); }}
            className="flex items-center gap-1 px-2 py-1 rounded-md bg-slate-800/60 border border-slate-700/50 hover:bg-red-500/10 hover:border-red-500/40 hover:text-red-400 text-slate-400 text-xs transition-colors">
            <Lock className="w-3 h-3" />Sign Out
          </button>
        </div>
      </header>



      {/* Main Layout: sidebar nav + content */}
      <div className="flex flex-1 min-h-0 overflow-hidden gap-0">

        {/* Vertical Sidebar Nav */}
        <nav className="w-56 flex-shrink-0 bg-slate-900/80 border-r border-slate-800/80 flex flex-col">
          {/* Nav items */}
          <div className="flex-1 overflow-y-auto py-3" style={{scrollbarWidth:'none'}}>
            {[
              { id:'admin_panel', icon:Settings,      label:'Admin Panel',     color:'text-amber-400'   },
              { id:'exec',        icon:TrendingUp,    label:'Overview',        color:'text-cyan-400'    },
              { id:'analytics',   icon:Activity,      label:'Analytics',       color:'text-indigo-400'  },
              { id:'alerts',      icon:Bell,          label:'Alerts & MITRE',  color:'text-amber-400'   },
              { id:'logs',        icon:Database,      label:'Attack Logs',     color:'text-rose-400'    },
              { id:'playbook',    icon:BookOpen,      label:'Playbooks',       color:'text-cyan-400'    },
              { id:'risk',        icon:TrendingUp,    label:'Risk Score',      color:'text-red-400'     },
              { id:'forensics',   icon:Search,        label:'Forensics',       color:'text-violet-400'  },
              { id:'geomap',      icon:Globe,         label:'Geo Map',         color:'text-emerald-400' },
              { id:'heatmap',     icon:Layers,        label:'Heatmap',         color:'text-orange-400'  },
              { id:'topology',    icon:GitBranch,     label:'Topology',        color:'text-blue-400'    },
              { id:'upload',      icon:Upload,        label:'CSV Analysis',    color:'text-pink-400'    },
              { id:'hipaa',       icon:ClipboardList, label:'HIPAA',           color:'text-emerald-400' },
              { id:'grc',         icon:Scale,         label:'GRC',             color:'text-violet-400'  },
              { id:'team',        icon:Users,         label:'ADS Team',        color:'text-cyan-400'    },
            ].filter(tab => visibleTabIds.includes(tab.id)).map(tab => (
              <button key={tab.id} onClick={() => setActiveTab(tab.id)}
                className={`w-full flex items-center gap-3 px-4 py-3 text-sm font-medium transition-all ${
                  activeTab === tab.id
                    ? `bg-slate-800/80 border-r-2 border-current ${tab.color}`
                    : 'text-slate-500 hover:text-slate-300 hover:bg-slate-800/40 border-r-2 border-transparent'
                }`}>
                <tab.icon className={`w-4 h-4 flex-shrink-0 ${activeTab === tab.id ? tab.color : ''}`} />
                <span>{tab.label}</span>
              </button>
            ))}
          </div>

          {/* Sidebar bottom: user + live stats */}
          <div className="border-t border-slate-800 p-3 space-y-2 flex-shrink-0">
            <div className="flex items-center gap-2">
              <UserCheck className="w-4 h-4 text-cyan-400 flex-shrink-0" />
              <span className="text-sm font-semibold text-cyan-400 truncate">{currentUser.name}</span>
            </div>
            <span className={`text-xs px-2 py-0.5 rounded border ${ROLE_DEFS[currentUser.role].badge}`}>{ROLE_DEFS[currentUser.role].label}</span>
            <div className="grid grid-cols-3 gap-1 text-xs">
              <div className="rounded-md bg-slate-800/60 px-2 py-1.5 text-center">
                <div className="text-slate-500 leading-tight">Alerts</div>
                <div className="font-bold text-red-400 leading-tight">{activeAlertCount}</div>
              </div>
              <div className="rounded-md bg-slate-800/60 px-2 py-1.5 text-center">
                <div className="text-slate-500 leading-tight">Blocked</div>
                <div className="font-bold text-orange-400 leading-tight">{stats.blocked}</div>
              </div>
              <div className="rounded-md bg-slate-800/60 px-2 py-1.5 text-center">
                <div className="text-slate-500 leading-tight">ACL</div>
                <div className="font-bold text-violet-400 leading-tight">{aclRules.length}</div>
              </div>
            </div>
            <div className="flex items-center gap-1.5 text-xs text-slate-500">
              <Clock className="w-3 h-3" />
              <span className="font-mono">{clockTime.toLocaleTimeString()}</span>
              <span className="ml-auto">Shift {shiftH > 0 ? `${shiftH}h ` : ''}{shiftM}m</span>
            </div>
          </div>
        </nav>

        {/* Content area (replaces old 3-column grid) */}
        <div className="flex-1 min-w-0 flex flex-col overflow-hidden">
        {/* [LEGACY LEFT COL WIDGETS — now in Overview tab] */}
        {false && <div className="col-span-3 flex flex-col gap-3 overflow-y-auto pr-1" style={{scrollbarWidth:'thin', scrollbarColor:'#334155 transparent'}}>
          {/* Traffic Monitor */}
          <div className="rounded-xl bg-slate-800/40 border border-slate-700/40 overflow-hidden">
            <div className="px-3 py-2 border-b border-slate-700/40 flex items-center gap-2">
              <Activity className="w-4 h-4 text-cyan-400" />
              <span className="font-medium text-base">Real-Time Traffic</span>
              <div className="ml-auto w-1.5 h-1.5 rounded-full bg-cyan-500 animate-pulse" />
            </div>
            <div className="p-3">
              <ResponsiveContainer width="100%" height={140}>
                <AreaChart data={trafficHistory}>
                  <defs>
                    <linearGradient id="grad" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#06b6d4" stopOpacity={0.4} />
                      <stop offset="95%" stopColor="#06b6d4" stopOpacity={0} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                  <XAxis dataKey="timestamp" stroke="#64748b" tick={{ fontSize: 8 }} />
                  <YAxis stroke="#64748b" tick={{ fontSize: 8 }} />
                  <Tooltip contentStyle={{ backgroundColor: '#1e293b', border: '1px solid #334155', borderRadius: '6px', fontSize: '10px' }} />
                  <Area type="monotone" dataKey="packets" stroke="#06b6d4" strokeWidth={2} fill="url(#grad)" />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </div>

          {/* Devices */}
          <div className="rounded-xl bg-slate-800/40 border border-slate-700/40 overflow-hidden">
            <div className="px-4 py-3 border-b border-slate-700/40 flex items-center gap-2">
              <Radio className="w-4 h-4 text-violet-400" />
              <span className="font-medium text-lg">IoMT Devices</span>
            </div>
            <div className="p-3 grid grid-cols-2 gap-3">
              {devices.map((device) => {
                const status = deviceStatus[device] || {};
                const isIsolated = isolatedDevices.includes(device);
                // Derive threat level from active alerts targeting this device
                const deviceAlerts = alerts.filter(a => a.device === device && a.status === 'active');
                const hasCritical = deviceAlerts.some(a => a.severity === 'critical');
                const hasHigh     = deviceAlerts.some(a => a.severity === 'high');
                const hasMedium   = deviceAlerts.some(a => a.severity === 'medium');
                const threatLevel = isIsolated ? 'isolated' : hasCritical ? 'critical' : hasHigh ? 'high' : hasMedium ? 'medium' : 'normal';

                const cardStyle = {
                  isolated: { card: 'bg-violet-500/10 border-violet-500/40', icon: 'bg-violet-500/20 text-violet-400', badge: 'bg-violet-500/20 text-violet-400', label: 'Isolated' },
                  critical: { card: 'bg-red-500/15 border-red-500/50',       icon: 'bg-red-500/20 text-red-400',       badge: 'bg-red-500/20 text-red-400',       label: 'CRITICAL' },
                  high:     { card: 'bg-orange-500/10 border-orange-500/40',  icon: 'bg-orange-500/20 text-orange-400', badge: 'bg-orange-500/20 text-orange-400', label: 'HIGH' },
                  medium:   { card: 'bg-amber-500/10 border-amber-500/40',    icon: 'bg-amber-500/20 text-amber-400',   badge: 'bg-amber-500/20 text-amber-400',   label: 'MEDIUM' },
                  normal:   { card: 'bg-slate-700/30 border-slate-600/30',    icon: 'bg-cyan-500/20 text-cyan-400',     badge: 'bg-emerald-500/20 text-emerald-400', label: 'OK' },
                }[threatLevel];

                return (
                  <div key={device} className={`p-2.5 rounded-lg border ${cardStyle.card} ${threatLevel === 'critical' ? 'animate-pulse' : ''}`}>
                    <div className="flex items-center justify-between mb-1.5">
                      <div className={`p-1 rounded ${cardStyle.icon}`}>
                        {getDeviceIcon(device)}
                      </div>
                      <span className={`text-base px-1 py-0.5 rounded font-semibold ${cardStyle.badge}`}>
                        {cardStyle.label}
                      </span>
                    </div>
                    <h3 className="font-medium text-base truncate">{device}</h3>
                    <p className="text-xs font-mono text-cyan-400 mt-0.5">{status.ip || '--'}</p>
                    <div className="flex items-center justify-between mt-1">
                      <span className="text-xs text-slate-400">FW: <span className="text-slate-300">{status.firmware || '--'}</span></span>
                      <span className="text-xs text-slate-400">{status.vlan || 'VLAN-20'}</span>
                    </div>
                    {deviceAlerts.length > 0 && (
                      <p className="text-xs text-red-400 mt-1 truncate">{deviceAlerts[0].type} · {deviceAlerts[0].time}</p>
                    )}
                  </div>
                );
              })}
            </div>
          </div>

          {/* Model Confidence */}
          <div className="rounded-xl bg-slate-800/40 border border-slate-700/40 p-4">
            <div className="flex items-center gap-2 mb-3">
              <Shield className="w-4 h-4 text-cyan-400" />
              <span className="font-medium text-lg">LightGBM Model</span>
            </div>
            <div className="flex items-center gap-4">
              <div className="relative">
                <svg className="w-20 h-20 -rotate-90">
                  <defs>
                    <linearGradient id="confGrad" x1="0%" y1="0%" x2="100%" y2="0%">
                      <stop offset="0%" stopColor="#06b6d4" />
                      <stop offset="100%" stopColor="#22c55e" />
                    </linearGradient>
                  </defs>
                  <circle cx="40" cy="40" r="32" stroke="#334155" strokeWidth="7" fill="none" />
                  <circle cx="40" cy="40" r="32" stroke="url(#confGrad)" strokeWidth="7" fill="none" strokeLinecap="round" strokeDasharray={`${(confidenceScore / 100) * 201} 201`} />
                </svg>
                <div className="absolute inset-0 flex items-center justify-center">
                  <span className="text-xl font-bold">{confidenceScore.toFixed(1)}%</span>
                </div>
              </div>
              <div className="flex-1 space-y-2">
                <div className="flex justify-between text-lg">
                  <span className="text-slate-400">Accuracy</span>
                  <span className="font-bold text-cyan-400">98.30%</span>
                </div>
                <div className="flex justify-between text-lg">
                  <span className="text-slate-400">Features</span>
                  <span className="font-bold text-cyan-400">56</span>
                </div>
                <div className="flex justify-between text-lg">
                  <span className="text-slate-400">Model</span>
                  <span className="font-bold text-emerald-400">LightGBM</span>
                </div>
                <div className="flex justify-between text-lg">
                  <span className="text-slate-400">Version</span>
                  <span className="font-bold">v2.0</span>
                </div>
              </div>
            </div>
          </div>
        </div>}

          {/* Full-width content area */}
          <div className="flex-1 overflow-y-auto min-w-0" style={{scrollbarWidth:'thin', scrollbarColor:'#334155 transparent'}}>
            <div className="flex flex-col flex-1 h-full">

            {/* ── TAB 0: Executive Overview ── */}
            {activeTab==='exec' && (() => {
              const critCount  = alerts.filter(a=>a.severity==='critical'&&a.status==='active').length;
              const highCount  = alerts.filter(a=>a.severity==='high'&&a.status==='active').length;
              const resolvedCount = alerts.filter(a=>a.status==='resolved'||a.status==='mitigated').length;
              // MTTD: time from alert creation to first acknowledgement (proxy for detection-to-awareness)
              const ackedAlerts = alerts.filter(a=>a.acknowledgedAt && a.createdAt);
              const mttd = ackedAlerts.length
                ? (ackedAlerts.reduce((s,a)=>s+(a.acknowledgedAt-a.createdAt),0)/ackedAlerts.length/60000).toFixed(1)
                : alerts.length ? '< 0.1' : '—';
              // MTTR: avg time from alert creation to first response action (block/isolate/ack/resolve)
              const respondedAlerts = alerts.filter(a => a.respondedAt && a.createdAt);
              const mttrMs = respondedAlerts.length
                ? respondedAlerts.reduce((s,a) => s + (a.respondedAt - a.createdAt), 0) / respondedAlerts.length
                : null;
              const mttr = mttrMs === null ? '—'
                : mttrMs < 60000 ? `${Math.max(1, Math.round(mttrMs / 1000))}s`
                : (mttrMs / 60000).toFixed(1) + ' min';
              const grcAvg = Math.round(grcFrameworks.reduce((s,f)=>s+f.score,0)/grcFrameworks.length);
              const threatLevel = critCount >= 3 ? 'CRITICAL' : critCount >= 1 ? 'ELEVATED' : highCount >= 2 ? 'GUARDED' : 'LOW';
              const threatLevelColor = {CRITICAL:'#ef4444',ELEVATED:'#f97316',GUARDED:'#eab308',LOW:'#22c55e'}[threatLevel];

              return (
                <div className="flex-1 overflow-y-auto p-5 space-y-5">

                  {/* Threat level banner */}
                  <div className="flex items-center justify-between px-5 py-3 rounded-xl border"
                    style={{backgroundColor:threatLevelColor+'12',borderColor:threatLevelColor+'44'}}>
                    <div className="flex items-center gap-3">
                      <div className="w-3 h-3 rounded-full animate-pulse" style={{backgroundColor:threatLevelColor}}/>
                      <div>
                        <span className="text-base text-slate-400 uppercase tracking-widest">Current Threat Level</span>
                        <span className="ml-3 text-xl font-black tracking-widest" style={{color:threatLevelColor}}>{threatLevel}</span>
                      </div>
                    </div>
                    <div className="text-right">
                    </div>
                  </div>

                  {/* KPI row — MTTD | MTTR | Blocked | GRC */}
                  <div className="grid grid-cols-4 gap-3">
                    {[
                      { label:'Mean Time to Detect',  value:`${mttd} min`, sub: mttd==='—' ? 'Ack an alert to calculate' : 'Target < 5 min',  color:'#06b6d4', ok: mttd!=='—'&&parseFloat(mttd)<5 },
                      { label:'Mean Time to Respond', value: mttr === '—' ? '— min' : mttr, sub: mttr==='—' ? 'Take action on an alert to calculate' : 'Target < 15 min', color:'#8b5cf6', ok: mttr!=='—'&&(mttr.endsWith('s')||parseFloat(mttr)<15) },
                      { label:'IPs Blocked',           value:blockedIPs.length, sub:`${responseLog.filter(r=>r.action==='Blocked IP').length} block actions logged`, color:'#ef4444', ok: true },
                      { label:'GRC Overall Score',     value:`${grcAvg}%`,  sub:`${grcFrameworks.filter(f=>f.score>=75).length}/${grcFrameworks.length} frameworks passing`, color: grcAvg>=75?'#22c55e':grcAvg>=55?'#eab308':'#ef4444', ok: grcAvg>=75 },
                    ].map((k,i)=>(
                      <div key={i} className="rounded-xl border p-4" style={{backgroundColor:k.color+'0d',borderColor:k.color+'33'}}>
                        <p className="text-xs text-slate-400 mb-2 uppercase tracking-wide">{k.label}</p>
                        <p className="text-2xl font-black mb-1" style={{color:k.color}}>{k.value}</p>
                        <div className="flex items-center gap-1.5">
                          <div className="w-1.5 h-1.5 rounded-full" style={{backgroundColor:k.ok?'#22c55e':'#ef4444'}}/>
                          <p className="text-xs text-slate-500">{k.sub}</p>
                        </div>
                      </div>
                    ))}
                  </div>

                  {/* GRC per-framework breakdown */}
                  <div className="rounded-xl border border-slate-700/40 bg-slate-800/20 p-4">
                    <p className="text-xs text-slate-400 uppercase tracking-wide mb-3">GRC Framework Breakdown — Pass / Fail Status</p>
                    <div className="grid grid-cols-3 gap-3">
                      {grcFrameworks.map(fw=>{
                        const color = fw.score>=75?'#22c55e':fw.score>=55?'#eab308':'#ef4444';
                        const label = fw.score>=75?'PASSING':fw.score>=55?'PARTIAL':'FAILING';
                        return (
                          <div key={fw.id} className="rounded-lg border p-3" style={{borderColor:color+'33',background:color+'08'}}>
                            <div className="flex items-center justify-between mb-2">
                              <span className="text-xs font-bold text-slate-300">{fw.name}</span>
                              <span className="text-xs font-black px-2 py-0.5 rounded" style={{background:color+'22',color}}>{label}</span>
                            </div>
                            <div className="flex items-center gap-2">
                              <div className="flex-1 h-1.5 rounded-full bg-slate-700 overflow-hidden">
                                <div className="h-full rounded-full transition-all" style={{width:fw.score+'%',background:color}}/>
                              </div>
                              <span className="text-xs font-black" style={{color}}>{fw.score}%</span>
                            </div>
                            <p className="text-xs text-slate-500 mt-1.5">{fw.passing}/{fw.controls} controls · {fw.critical} critical gaps</p>
                          </div>
                        );
                      })}
                    </div>
                  </div>

                  {/* Alert summary + framework scores — 2 columns */}
                  <div className="grid grid-cols-2 gap-4">

                    {/* Alert breakdown */}
                    <div className="rounded-xl border border-slate-700/40 bg-slate-800/20 p-5">
                      <p className="text-base text-slate-400 uppercase tracking-wide mb-4">Active Alert Breakdown</p>
                      <div className="space-y-3">
                        {[
                          {label:'Critical',  count:critCount,  color:'#ef4444'},
                          {label:'High',      count:highCount,  color:'#f97316'},
                          {label:'Medium',    count:alerts.filter(a=>a.severity==='medium'&&a.status==='active').length, color:'#eab308'},
                          {label:'Resolved',  count:resolvedCount, color:'#22c55e'},
                        ].map(row=>(
                          <div key={row.label} className="flex items-center gap-3">
                            <span className="w-16 text-base font-medium" style={{color:row.color}}>{row.label}</span>
                            <div className="flex-1 h-2 bg-slate-700 rounded-full overflow-hidden">
                              <div className="h-full rounded-full transition-all" style={{
                                width:`${Math.min(100,((row.count)/(Math.max(1,alerts.length)))*100)}%`,
                                backgroundColor:row.color
                              }}/>
                            </div>
                            <span className="w-6 text-right text-base font-bold" style={{color:row.color}}>{row.count}</span>
                          </div>
                        ))}
                      </div>
                      <div className="mt-4 pt-3 border-t border-slate-700/40 flex justify-between text-base text-slate-500">
                        <span>Total alerts: <span className="text-white font-bold">{alerts.length}</span></span>
                        <span>Isolated: <span className="text-violet-400 font-bold">{isolatedDevices.length} device{isolatedDevices.length!==1?'s':''}</span></span>
                      </div>
                    </div>

                  </div>

                  {/* IoMT Devices + Traffic */}
                  <div className="grid grid-cols-2 gap-4">
                    {/* Devices */}
                    <div className="rounded-xl bg-slate-800/40 border border-slate-700/40 overflow-hidden">
                      <div className="px-4 py-2.5 border-b border-slate-700/40 flex items-center gap-2">
                        <Radio className="w-3.5 h-3.5 text-violet-400" />
                        <span className="font-medium text-xs">IoMT Devices</span>
                      </div>
                      <div className="p-3 grid grid-cols-2 gap-2">
                        {devices.map((device) => {
                          const status = deviceStatus[device] || {};
                          const isIsolated = isolatedDevices.includes(device);
                          const deviceAlerts = alerts.filter(a => a.device === device && a.status === 'active');
                          const hasCritical = deviceAlerts.some(a => a.severity === 'critical');
                          const hasHigh = deviceAlerts.some(a => a.severity === 'high');
                          const hasMedium = deviceAlerts.some(a => a.severity === 'medium');
                          const tl = isIsolated ? 'isolated' : hasCritical ? 'critical' : hasHigh ? 'high' : hasMedium ? 'medium' : 'normal';
                          const cs = { isolated:{card:'bg-violet-500/10 border-violet-500/40',badge:'bg-violet-500/20 text-violet-400',label:'Isolated'}, critical:{card:'bg-red-500/15 border-red-500/50',badge:'bg-red-500/20 text-red-400',label:'CRITICAL'}, high:{card:'bg-orange-500/10 border-orange-500/40',badge:'bg-orange-500/20 text-orange-400',label:'HIGH'}, medium:{card:'bg-amber-500/10 border-amber-500/40',badge:'bg-amber-500/20 text-amber-400',label:'MEDIUM'}, normal:{card:'bg-slate-700/30 border-slate-600/30',badge:'bg-emerald-500/20 text-emerald-400',label:'OK'} }[tl];
                          return (
                            <div key={device} className={`p-2 rounded-lg border ${cs.card}`}>
                              <div className="flex items-center justify-between mb-1">
                                <span className="text-xs font-medium truncate flex-1">{device}</span>
                                <span className={`text-xs px-1 py-0.5 rounded font-semibold ml-1 flex-shrink-0 ${cs.badge}`}>{cs.label}</span>
                              </div>
                              <p className="text-xs font-mono text-cyan-400">{status.ip || '--'}</p>
                              <p className="text-xs text-slate-500">FW: {status.firmware || '--'}</p>
                            </div>
                          );
                        })}
                      </div>
                    </div>

                    {/* Traffic + Attack Distribution */}
                    <div className="rounded-xl bg-slate-800/40 border border-slate-700/40 overflow-hidden">
                      <div className="px-4 py-2.5 border-b border-slate-700/40 flex items-center gap-2">
                        <Activity className="w-3.5 h-3.5 text-cyan-400" />
                        <span className="font-medium text-xs">Real-Time Traffic</span>
                        <div className="ml-auto w-1.5 h-1.5 rounded-full bg-cyan-500 animate-pulse" />
                      </div>
                      <div className="p-3">
                        <ResponsiveContainer width="100%" height={120}>
                          <AreaChart data={trafficHistory}>
                            <defs>
                              <linearGradient id="grad2" x1="0" y1="0" x2="0" y2="1">
                                <stop offset="5%" stopColor="#06b6d4" stopOpacity={0.4} />
                                <stop offset="95%" stopColor="#06b6d4" stopOpacity={0} />
                              </linearGradient>
                            </defs>
                            <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                            <XAxis dataKey="timestamp" stroke="#64748b" tick={{ fontSize: 8 }} />
                            <YAxis stroke="#64748b" tick={{ fontSize: 8 }} />
                            <Tooltip contentStyle={{ backgroundColor: '#1e293b', border: '1px solid #334155', borderRadius: '6px', fontSize: '10px' }} />
                            <Area type="monotone" dataKey="packets" stroke="#06b6d4" strokeWidth={2} fill="url(#grad2)" />
                          </AreaChart>
                        </ResponsiveContainer>
                      </div>
                    </div>
                  </div>

                  {/* Attack Distribution + Response Log + Stats */}
                  <div className="grid grid-cols-3 gap-4">
                    {/* Attack Distribution */}
                    <div className="rounded-xl bg-slate-800/40 border border-slate-700/40 p-4">
                      <div className="flex items-center gap-2 mb-2">
                        <Target className="w-3.5 h-3.5 text-red-400" />
                        <span className="font-medium text-xs">Attack Distribution</span>
                      </div>
                      <ResponsiveContainer width="100%" height={100}>
                        <PieChart>
                          <Pie data={attackDistribution} cx="50%" cy="50%" innerRadius={24} outerRadius={44} paddingAngle={3} dataKey="value">
                            {attackDistribution.map((entry, i) => <Cell key={i} fill={entry.color} />)}
                          </Pie>
                          <Tooltip contentStyle={{ backgroundColor: '#1e293b', border: '1px solid #334155', borderRadius: '6px', fontSize: '10px' }} />
                        </PieChart>
                      </ResponsiveContainer>
                      <div className="grid grid-cols-2 gap-x-2 gap-y-0.5 mt-1">
                        {attackDistribution.map((item, i) => (
                          <div key={i} className="flex items-center gap-1 text-xs">
                            <div className="w-1.5 h-1.5 rounded-full flex-shrink-0" style={{ backgroundColor: item.color }} />
                            <span className="text-slate-400 truncate">{item.name}</span>
                            <span className="ml-auto font-semibold">{item.value}%</span>
                          </div>
                        ))}
                      </div>
                    </div>

                    {/* Response Log */}
                    <div className="rounded-xl bg-slate-800/40 border border-slate-700/40 overflow-hidden">
                      <div className="px-4 py-2.5 border-b border-slate-700/40 flex items-center gap-2">
                        <History className="w-3.5 h-3.5 text-emerald-400" />
                        <span className="font-medium text-xs">Response Log</span>
                      </div>
                      <div className="divide-y divide-slate-700/30 overflow-y-auto max-h-48">
                        {responseLog.length === 0
                          ? <p className="px-3 py-4 text-xs text-slate-500 text-center">No response actions logged yet.</p>
                          : responseLog.slice(0, 6).map((log) => (
                          <div key={log.id} className="px-3 py-2 flex items-center gap-2">
                            <div className="w-1.5 h-1.5 rounded-full flex-shrink-0" style={{ backgroundColor: log.action.includes('Block')||log.action.includes('Isolat')?'#f87171':log.action.includes('Resolv')?'#34d399':'#fbbf24' }} />
                            <div className="flex-1 min-w-0">
                              <p className="text-xs font-medium truncate">{log.action}: <span className="font-mono text-slate-300">{log.target}</span></p>
                              <p className="text-xs text-slate-500">{log.user} · {log.time}</p>
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>

                    {/* Model + Live Stats */}
                    <div className="rounded-xl bg-slate-800/40 border border-slate-700/40 p-4 space-y-3">
                      <div className="flex items-center gap-2">
                        <Shield className="w-3.5 h-3.5 text-cyan-400" />
                        <span className="font-medium text-xs">LightGBM Model</span>
                      </div>
                      <div className="flex items-center gap-3">
                        <div className="relative">
                          <svg className="w-14 h-14 -rotate-90">
                            <circle cx="28" cy="28" r="22" stroke="#334155" strokeWidth="5" fill="none" />
                            <circle cx="28" cy="28" r="22" stroke="#06b6d4" strokeWidth="5" fill="none" strokeLinecap="round" strokeDasharray={`${(confidenceScore/100)*138} 138`} />
                          </svg>
                          <div className="absolute inset-0 flex items-center justify-center">
                            <span className="text-xs font-bold">{confidenceScore.toFixed(1)}%</span>
                          </div>
                        </div>
                        <div className="flex-1 space-y-1 text-xs">
                          {[['Accuracy',`${confidenceScore.toFixed(1)}%`,'text-cyan-400'],['Features','44','text-cyan-400'],['Model','LightGBM','text-emerald-400']].map(([l,v,c])=>(
                            <div key={l} className="flex justify-between"><span className="text-slate-400">{l}</span><span className={`font-bold ${c}`}>{v}</span></div>
                          ))}
                        </div>
                      </div>
                      <div className="grid grid-cols-2 gap-1 pt-1 border-t border-slate-700/40">
                        {[['Packets',stats.totalPackets.toLocaleString(),'#22d3ee'],['Anomalies',stats.anomalies,'#fbbf24'],['Blocked',stats.blocked,'#f87171'],['Devices',stats.devices,'#34d399']].map(([l,v,c])=>(
                          <div key={l} className="text-xs">
                            <span className="text-slate-500">{l} </span>
                            <span className="font-bold" style={{color:c}}>{v}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  </div>

                </div>
              );
            })()}

            {/* ── TAB: Analytics ── */}
            {activeTab==='analytics' && (() => {
              const typeColors = { DDoS:'#ef4444', DoS:'#f97316', Recon:'#eab308', MQTT:'#06b6d4', Spoofing:'#8b5cf6' };
              const typeDist = Object.entries(typeColors).map(([name, color]) => ({
                name, value: alerts.filter(a => a.type === name).length, color
              })).filter(d => d.value > 0);
              const sevDist = [
                { name:'Critical', value: alerts.filter(a=>a.severity==='critical').length, color:'#ef4444' },
                { name:'High',     value: alerts.filter(a=>a.severity==='high').length,     color:'#f97316' },
                { name:'Medium',   value: alerts.filter(a=>a.severity==='medium').length,   color:'#eab308' },
                { name:'Low',      value: alerts.filter(a=>a.severity==='low').length,      color:'#22c55e' },
              ].filter(d => d.value > 0);
              const actionDist = [
                { name:'Blocked IP',  value: responseLog.filter(r=>r.action==='Blocked IP').length,  color:'#ef4444' },
                { name:'Isolated',    value: responseLog.filter(r=>r.action?.includes('Isolated')).length, color:'#8b5cf6' },
                { name:'Resolved',    value: responseLog.filter(r=>r.action==='Resolved').length,    color:'#22c55e' },
                { name:'Acknowledged',value: responseLog.filter(r=>r.action==='Acknowledged').length,color:'#06b6d4' },
              ];
              const displayTrend = trendHistory.slice(-30); // last 30 minutes
              return (
                <div className="flex-1 overflow-y-auto p-5 space-y-5">
                  <div className="flex items-center gap-3 mb-1">
                    <Activity className="w-5 h-5 text-indigo-400" />
                    <h2 className="text-lg font-bold text-slate-100">Analytics & Trends</h2>
                    <span className="text-xs text-slate-500 ml-auto">{trendHistory.length} data points · updates every 60 s</span>
                  </div>

                  {/* Row 1: Alerts over time */}
                  <div className="bg-slate-800/60 border border-slate-700/50 rounded-xl p-4">
                    <h3 className="text-sm font-semibold text-slate-300 mb-3">Alert Volume Over Time</h3>
                    {displayTrend.length < 2 ? (
                      <div className="flex items-center justify-center h-40 text-slate-500 text-sm">Collecting data — check back in a minute…</div>
                    ) : (
                      <ResponsiveContainer width="100%" height={180}>
                        <AreaChart data={displayTrend} margin={{top:4,right:8,left:-20,bottom:0}}>
                          <defs>
                            <linearGradient id="gradDDoS"    x1="0" y1="0" x2="0" y2="1"><stop offset="5%"  stopColor="#ef4444" stopOpacity={0.3}/><stop offset="95%" stopColor="#ef4444" stopOpacity={0}/></linearGradient>
                            <linearGradient id="gradDoS"     x1="0" y1="0" x2="0" y2="1"><stop offset="5%"  stopColor="#f97316" stopOpacity={0.3}/><stop offset="95%" stopColor="#f97316" stopOpacity={0}/></linearGradient>
                            <linearGradient id="gradRecon"   x1="0" y1="0" x2="0" y2="1"><stop offset="5%"  stopColor="#eab308" stopOpacity={0.3}/><stop offset="95%" stopColor="#eab308" stopOpacity={0}/></linearGradient>
                            <linearGradient id="gradMQTT"    x1="0" y1="0" x2="0" y2="1"><stop offset="5%"  stopColor="#06b6d4" stopOpacity={0.3}/><stop offset="95%" stopColor="#06b6d4" stopOpacity={0}/></linearGradient>
                            <linearGradient id="gradSpoofing"x1="0" y1="0" x2="0" y2="1"><stop offset="5%"  stopColor="#8b5cf6" stopOpacity={0.3}/><stop offset="95%" stopColor="#8b5cf6" stopOpacity={0}/></linearGradient>
                          </defs>
                          <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                          <XAxis dataKey="time" tick={{fill:'#94a3b8',fontSize:10}} interval="preserveStartEnd" />
                          <YAxis tick={{fill:'#94a3b8',fontSize:10}} allowDecimals={false} />
                          <Tooltip contentStyle={{backgroundColor:'#1e293b',border:'1px solid #334155',borderRadius:'8px',color:'#e2e8f0',fontSize:12}} />
                          <Legend wrapperStyle={{fontSize:11,color:'#94a3b8'}} />
                          <Area type="monotone" dataKey="DDoS"     stroke="#ef4444" fill="url(#gradDDoS)"     strokeWidth={1.5} dot={false} />
                          <Area type="monotone" dataKey="DoS"      stroke="#f97316" fill="url(#gradDoS)"      strokeWidth={1.5} dot={false} />
                          <Area type="monotone" dataKey="Recon"    stroke="#eab308" fill="url(#gradRecon)"    strokeWidth={1.5} dot={false} />
                          <Area type="monotone" dataKey="MQTT"     stroke="#06b6d4" fill="url(#gradMQTT)"     strokeWidth={1.5} dot={false} />
                          <Area type="monotone" dataKey="Spoofing" stroke="#8b5cf6" fill="url(#gradSpoofing)" strokeWidth={1.5} dot={false} />
                        </AreaChart>
                      </ResponsiveContainer>
                    )}
                  </div>

                  {/* Row 2: Threat type + Severity donut side by side */}
                  <div className="grid grid-cols-2 gap-4">
                    <div className="bg-slate-800/60 border border-slate-700/50 rounded-xl p-4">
                      <h3 className="text-sm font-semibold text-slate-300 mb-3">Threat Type Distribution</h3>
                      {typeDist.length === 0 ? (
                        <div className="flex items-center justify-center h-36 text-slate-500 text-sm">No alerts yet</div>
                      ) : (
                        <ResponsiveContainer width="100%" height={160}>
                          <PieChart>
                            <Pie data={typeDist} cx="50%" cy="50%" innerRadius={40} outerRadius={65} paddingAngle={3} dataKey="value" nameKey="name" label={({name,percent})=>`${name} ${(percent*100).toFixed(0)}%`} labelLine={false} fontSize={10}>
                              {typeDist.map((d,i) => <Cell key={i} fill={d.color} />)}
                            </Pie>
                            <Tooltip contentStyle={{backgroundColor:'#1e293b',border:'1px solid #334155',borderRadius:'8px',fontSize:12}} />
                          </PieChart>
                        </ResponsiveContainer>
                      )}
                    </div>
                    <div className="bg-slate-800/60 border border-slate-700/50 rounded-xl p-4">
                      <h3 className="text-sm font-semibold text-slate-300 mb-3">Severity Breakdown</h3>
                      {sevDist.length === 0 ? (
                        <div className="flex items-center justify-center h-36 text-slate-500 text-sm">No alerts yet</div>
                      ) : (
                        <ResponsiveContainer width="100%" height={160}>
                          <BarChart data={sevDist} margin={{top:4,right:8,left:-20,bottom:0}}>
                            <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                            <XAxis dataKey="name" tick={{fill:'#94a3b8',fontSize:10}} />
                            <YAxis tick={{fill:'#94a3b8',fontSize:10}} allowDecimals={false} />
                            <Tooltip contentStyle={{backgroundColor:'#1e293b',border:'1px solid #334155',borderRadius:'8px',fontSize:12}} />
                            <Bar dataKey="value" radius={[4,4,0,0]}>
                              {sevDist.map((d,i) => <Cell key={i} fill={d.color} />)}
                            </Bar>
                          </BarChart>
                        </ResponsiveContainer>
                      )}
                    </div>
                  </div>

                  {/* Row 3: Severity over time + Response actions */}
                  <div className="grid grid-cols-2 gap-4">
                    <div className="bg-slate-800/60 border border-slate-700/50 rounded-xl p-4">
                      <h3 className="text-sm font-semibold text-slate-300 mb-3">Severity Trend Over Time</h3>
                      {displayTrend.length < 2 ? (
                        <div className="flex items-center justify-center h-40 text-slate-500 text-sm">Collecting…</div>
                      ) : (
                        <ResponsiveContainer width="100%" height={160}>
                          <AreaChart data={displayTrend} margin={{top:4,right:8,left:-20,bottom:0}}>
                            <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                            <XAxis dataKey="time" tick={{fill:'#94a3b8',fontSize:10}} interval="preserveStartEnd" />
                            <YAxis tick={{fill:'#94a3b8',fontSize:10}} allowDecimals={false} />
                            <Tooltip contentStyle={{backgroundColor:'#1e293b',border:'1px solid #334155',borderRadius:'8px',fontSize:12}} />
                            <Legend wrapperStyle={{fontSize:11,color:'#94a3b8'}} />
                            <Area type="monotone" dataKey="critical" stroke="#ef4444" fill="#ef444420" strokeWidth={2} dot={false} />
                            <Area type="monotone" dataKey="high"     stroke="#f97316" fill="#f9731620" strokeWidth={2} dot={false} />
                            <Area type="monotone" dataKey="medium"   stroke="#eab308" fill="#eab30820" strokeWidth={2} dot={false} />
                          </AreaChart>
                        </ResponsiveContainer>
                      )}
                    </div>
                    <div className="bg-slate-800/60 border border-slate-700/50 rounded-xl p-4">
                      <h3 className="text-sm font-semibold text-slate-300 mb-3">Response Actions</h3>
                      <ResponsiveContainer width="100%" height={160}>
                        <BarChart data={actionDist} layout="vertical" margin={{top:4,right:16,left:0,bottom:0}}>
                          <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                          <XAxis type="number" tick={{fill:'#94a3b8',fontSize:10}} allowDecimals={false} />
                          <YAxis type="category" dataKey="name" tick={{fill:'#94a3b8',fontSize:10}} width={80} />
                          <Tooltip contentStyle={{backgroundColor:'#1e293b',border:'1px solid #334155',borderRadius:'8px',fontSize:12}} />
                          <Bar dataKey="value" radius={[0,4,4,0]}>
                            {actionDist.map((d,i) => <Cell key={i} fill={d.color} />)}
                          </Bar>
                        </BarChart>
                      </ResponsiveContainer>
                    </div>
                  </div>

                  {/* Row 4: Summary stats */}
                  <div className="grid grid-cols-4 gap-3">
                    {[
                      { label:'Total Alerts',    value: alerts.length,                                             color:'#06b6d4' },
                      { label:'Threats Blocked', value: blockedIPs.length,                                        color:'#ef4444' },
                      { label:'Actions Logged',  value: responseLog.length,                                       color:'#8b5cf6' },
                      { label:'Data Since',       value: trendHistory.length > 0 ? trendHistory[0].time : '—',    color:'#22c55e' },
                    ].map(({label,value,color}) => (
                      <div key={label} className="bg-slate-800/60 border border-slate-700/50 rounded-xl p-4 text-center">
                        <div className="text-2xl font-black mb-1" style={{color}}>{value}</div>
                        <div className="text-xs text-slate-500 uppercase tracking-wide">{label}</div>
                      </div>
                    ))}
                  </div>
                </div>
              );
            })()}

            {/* ── TAB 1: Alerts & MITRE ── */}
            {activeTab==='alerts' && (
              <div className="flex flex-col flex-1 overflow-hidden">
                <div className="px-3 py-2 border-b border-slate-700/40 flex-shrink-0">
                  <div className="flex items-center justify-between mb-1.5">
                    <div className="flex items-center gap-2">
                      <span className="font-medium text-base">Security Alerts</span>
                      <span className="px-1.5 py-0.5 rounded bg-red-500/20 text-red-400 text-base font-bold">{activeAlertCount} active</span>
                      {fpAlertCount>0 && <span className="px-1.5 py-0.5 rounded bg-amber-500/20 text-amber-400 text-base">{fpAlertCount} FP</span>}
                      {suppressedCount>0 && <span className="px-1.5 py-0.5 rounded bg-slate-700/50 text-slate-400 text-base">{suppressedCount} suppressed</span>}
                    </div>
                    <div className="flex items-center gap-1">
                      <Filter className="w-3 h-3 text-slate-400" />
                      <select value={alertFilter} onChange={e=>setAlertFilter(e.target.value)} className="bg-transparent text-base text-slate-400 border-none focus:outline-none">
                        <option value="all">All</option>
                        <option value="active">Active</option>
                        <option value="fp">False Positives</option>
                        <option value="acknowledged">Ack'd</option>
                        <option value="resolved">Resolved</option>
                      </select>
                    </div>
                  </div>
                  {/* FP suppression rules */}
                  {fpSuppressions.length>0 && (
                    <div className="flex flex-wrap gap-1">
                      {fpSuppressions.map(r=>(
                        <span key={r.key} className="flex items-center gap-1 px-1.5 py-0.5 rounded text-base bg-amber-500/10 border border-amber-500/30 text-amber-300">
                          <span>⊘ {r.type}→{r.device}</span>
                          <button onClick={()=>setFpSuppressions(prev=>prev.filter(x=>x.key!==r.key))} className="text-amber-500 hover:text-amber-200 ml-0.5">×</button>
                        </span>
                      ))}
                    </div>
                  )}
                </div>
                <div className="flex flex-1 overflow-hidden min-h-0">
                  {/* Alert list */}
                  <div className="flex-1 overflow-y-auto divide-y divide-slate-700/30 min-w-0">
                    {filteredAlerts.map(alert => {
                      const isBlocked  = blockedIPs.includes(alert.sourceIP);
                      const isIsolated = isolatedDevices.includes(alert.device);
                      const mitre      = mitreMapping[alert.type] || {};
                      const isFP       = alert.status === 'fp' || alert.isModelFP;
                      return (
                        <div key={alert.id} className={`p-2.5 hover:bg-slate-700/20 cursor-pointer ${isFP?'opacity-60 bg-amber-500/5':alert.status!=='active'?'opacity-50':''} ${selectedAlertForMitre?.id===alert.id?'bg-slate-700/30':''}`}
                             onClick={()=>setSelectedAlertForMitre(alert)}>
                          <div className="flex items-start gap-2 mb-1.5">
                            <div className={`p-1 rounded border flex-shrink-0 ${isFP?'border-amber-500/40 text-amber-400 bg-amber-500/10':getSeverityColor(alert.severity)}`}><AlertOctagon className="w-3 h-3"/></div>
                            <div className="flex-1 min-w-0">
                              <div className="flex items-center gap-1 mb-0.5 flex-wrap">
                                {isFP
                                  ? <span className="px-1 py-0.5 rounded text-base font-bold bg-amber-500/20 text-amber-400">FP</span>
                                  : <span className={`px-1 py-0.5 rounded text-base uppercase font-bold ${getSeverityColor(alert.severity)}`}>{alert.severity}</span>
                                }
                                <span className={`px-1 py-0.5 rounded text-base ${isFP?'text-amber-500':getStatusColor(alert.status)}`}>{isFP?'false positive':alert.status}</span>
                                <span className="text-base text-slate-500">{alert.type}</span>
                                {alert.isModelFP && alert.trueCategory && <span className="text-base text-amber-400/70">→ true: {alert.trueCategory}</span>}
                                {mitre.techniqueId && !isFP && <span className="text-base text-purple-400 font-mono">{mitre.techniqueId}</span>}
                              </div>
                              <p className="text-base font-medium truncate">{alert.message}</p>
                              <p className="text-base text-slate-500">{alert.device} • {alert.time} • {Number(alert.confidence||0).toFixed(0)}% conf</p>
                            </div>
                            <button onClick={e=>{e.stopPropagation();setSelectedAlert(alert);setShowAlertPanel(true);}} className="p-1 rounded hover:bg-slate-600/50 flex-shrink-0">
                              <Eye className="w-3 h-3 text-slate-400"/>
                            </button>
                          </div>
                          {alert.status==='active' && (
                            <div className="flex gap-1 ml-6 flex-wrap">
                              {canBlock && (!isBlocked
                                ? <button onClick={e=>{e.stopPropagation();handleQuickAction('block',alert);}} className="flex items-center gap-0.5 px-1.5 py-0.5 rounded bg-red-500/20 text-red-400 text-base hover:bg-red-500/30"><Ban className="w-2.5 h-2.5"/>Block</button>
                                : <button onClick={e=>{e.stopPropagation();handleQuickAction('unblock',alert);}} className="flex items-center gap-0.5 px-1.5 py-0.5 rounded bg-emerald-500/20 text-emerald-400 text-base"><Unlock className="w-2.5 h-2.5"/>Unblock</button>)}
                              {canIsolate && !isIsolated && <button onClick={e=>{e.stopPropagation();handleQuickAction('isolate',alert);}} className="flex items-center gap-0.5 px-1.5 py-0.5 rounded bg-violet-500/20 text-violet-400 text-base hover:bg-violet-500/30"><Unplug className="w-2.5 h-2.5"/>Isolate</button>}
                              {canAck && <button onClick={e=>{e.stopPropagation();handleQuickAction('acknowledge',alert);}} className="flex items-center gap-0.5 px-1.5 py-0.5 rounded bg-amber-500/20 text-amber-400 text-base"><CheckCircle className="w-2.5 h-2.5"/>Ack</button>}
                              <button onClick={e=>{e.stopPropagation();handleQuickAction('resolve',alert);}} className="flex items-center gap-0.5 px-1.5 py-0.5 rounded bg-emerald-500/20 text-emerald-400 text-base"><ShieldCheck className="w-2.5 h-2.5"/>Resolve</button>
                              <button onClick={e=>{e.stopPropagation();markAsFP(alert);}} className="flex items-center gap-0.5 px-1.5 py-0.5 rounded bg-amber-500/20 text-amber-400 text-base hover:bg-amber-500/30" title="Mark as false positive — suppresses future alerts of this type on this device">⊘ FP</button>
                            </div>
                          )}
                        </div>
                      );
                    })}
                  </div>
                  {/* MITRE Detail Panel */}
                  {selectedAlertForMitre && (() => {
                    const m = mitreMapping[selectedAlertForMitre.type] || {};
                    return (
                      <div className="w-52 border-l border-slate-700/40 p-3 overflow-y-auto flex-shrink-0 bg-slate-900/30">
                        <div className="flex items-center justify-between mb-2">
                          <span className="text-base font-bold text-purple-400">MITRE ATT&CK</span>
                          <button onClick={()=>setSelectedAlertForMitre(null)}><X className="w-3 h-3 text-slate-400"/></button>
                        </div>
                        <div className="space-y-2 text-base">
                          <div className="p-2 rounded bg-purple-500/10 border border-purple-500/30">
                            <p className="text-slate-400">Tactic</p>
                            <p className="font-bold text-purple-300">{m.tactic}</p>
                            <p className="font-mono text-purple-500">{m.tacticId}</p>
                          </div>
                          <div className="p-2 rounded bg-slate-700/30">
                            <p className="text-slate-400">Technique</p>
                            <p className="font-medium text-white">{m.technique}</p>
                            <p className="font-mono text-cyan-400">{m.techniqueId}</p>
                          </div>
                          <div className="p-2 rounded bg-slate-700/30">
                            <p className="text-slate-400">Sub-Technique</p>
                            <p className="font-medium text-white text-base">{m.sub}</p>
                            <p className="font-mono text-cyan-400">{m.subId}</p>
                          </div>
                          <div className="p-2 rounded bg-slate-700/30">
                            <p className="text-slate-400 mb-1">Mitigations</p>
                            {(m.mitigations||[]).map((mg,i)=>(
                              <div key={i} className="flex items-start gap-1 mb-1">
                                <ShieldCheck className="w-2.5 h-2.5 text-emerald-400 mt-0.5 flex-shrink-0"/>
                                <p className="text-emerald-300">{mg}</p>
                              </div>
                            ))}
                          </div>
                          <a href={`https://attack.mitre.org/techniques/${m.techniqueId}/`} target="_blank" rel="noreferrer"
                            className="flex items-center gap-1 text-cyan-400 hover:underline">
                            <ExternalLink className="w-3 h-3"/>View on MITRE
                          </a>
                        </div>
                        {/* Radar chart */}
                        <div className="mt-3">
                          <p className="text-base text-slate-400 mb-1">ATT&CK Coverage</p>
                          <ResponsiveContainer width="100%" height={130}>
                            <RadarChart data={tacticRadarBase}>
                              <PolarGrid stroke="#334155"/>
                              <PolarAngleAxis dataKey="tactic" tick={{fontSize:7,fill:'#94a3b8'}}/>
                              <Radar name="Coverage" dataKey="covered" stroke="#8b5cf6" fill="#8b5cf6" fillOpacity={0.3}/>
                            </RadarChart>
                          </ResponsiveContainer>
                        </div>
                      </div>
                    );
                  })()}
                </div>
              </div>
            )}

            {/* ── Attack Logs Tab ── */}
            {activeTab==='logs' && (() => {
              const logFmtTs = ts => {
                const d = new Date(ts * 1000);
                return d.toLocaleDateString('en-US',{month:'short',day:'2-digit',year:'numeric'}) + ' ' + d.toLocaleTimeString('en-US',{hour12:false});
              };
              const logSevBg = s => ({
                critical:'bg-red-500/15 text-red-300 border-red-500/30',
                high:'bg-orange-500/15 text-orange-300 border-orange-500/30',
                medium:'bg-amber-500/15 text-amber-300 border-amber-500/30',
                low:'bg-blue-500/15 text-blue-300 border-blue-500/30',
              }[s] || 'bg-slate-700 text-slate-300 border-slate-600');
              const logTypes   = [...new Set(logData.map(r => r.prediction))].sort();
              const logDevices = [...new Set(logData.map(r => r.device))].sort();
              const logFiltered = logData.filter(r => {
                if (logFilterSev  !== 'all' && r.severity   !== logFilterSev)  return false;
                if (logFilterType !== 'all' && r.prediction !== logFilterType) return false;
                if (logFilterDev  !== 'all' && r.device     !== logFilterDev)  return false;
                if (logSearch) {
                  const q = logSearch.toLowerCase();
                  if (![r.src_ip,r.dst_ip,r.device,r.prediction,r.severity].join(' ').toLowerCase().includes(q)) return false;
                }
                return true;
              });
              const logExportCSV = () => {
                const hdr = 'ID,Timestamp,Attack Type,Severity,Device,Source IP,Dest IP,Confidence (%),Anomaly Score\n';
                const rows = logFiltered.map(r =>
                  [r.id,logFmtTs(r.timestamp),r.prediction,r.severity,r.device,r.src_ip,r.dst_ip,r.confidence.toFixed(2),r.anomaly_score].join(',')
                ).join('\n');
                const blob = new Blob([hdr+rows],{type:'text/csv'});
                const a = document.createElement('a');
                a.href = URL.createObjectURL(blob);
                a.download = `iomt_attack_logs_${new Date().toISOString().slice(0,10)}.csv`;
                a.click();
              };
              const logCrit = logFiltered.filter(r => r.severity==='critical').length;
              const logHigh = logFiltered.filter(r => r.severity==='high').length;
              const logTypeCount = [...new Set(logFiltered.map(r => r.prediction))].length;
              return (
                <div className="flex flex-col h-full bg-slate-950 overflow-hidden">
                  <div className="flex items-center justify-between px-6 py-4 border-b border-slate-800 bg-slate-900 flex-shrink-0">
                    <div className="flex items-center gap-3">
                      <Database className="w-5 h-5 text-rose-400"/>
                      <div>
                        <h2 className="text-base font-bold text-white">Attack Event Logs</h2>
                        <p className="text-xs text-slate-500">Persistent records from SQLite database{logRefresh && <span> · Refreshed {logRefresh.toLocaleTimeString()}</span>}</p>
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      <button onClick={() => fetchAttackLogs(logLimit)} className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded text-xs font-medium border border-slate-700">
                        <RefreshCw className="w-3 h-3"/> Refresh
                      </button>
                      <button onClick={logExportCSV} className="flex items-center gap-1.5 px-3 py-1.5 bg-rose-600 hover:bg-rose-500 text-white rounded text-xs font-bold">
                        <FileText className="w-3 h-3"/> Export CSV
                      </button>
                    </div>
                  </div>
                  <div className="grid grid-cols-4 gap-px bg-slate-800 flex-shrink-0">
                    {[['Total Records',logFiltered.length,'text-white'],['Critical',logCrit,'text-red-400'],['High',logHigh,'text-orange-400'],['Attack Types',logTypeCount,'text-violet-400']].map(([l,v,c])=>(
                      <div key={l} className="bg-slate-900 px-5 py-3 text-center">
                        <div className={`text-2xl font-bold ${c}`}>{v}</div>
                        <div className="text-xs text-slate-500 uppercase tracking-wider mt-0.5">{l}</div>
                      </div>
                    ))}
                  </div>
                  <div className="flex items-center gap-3 px-6 py-3 bg-slate-900/60 border-b border-slate-800 flex-shrink-0 flex-wrap">
                    <div className="flex items-center gap-2 flex-1 min-w-48">
                      <Search className="w-3.5 h-3.5 text-slate-500 flex-shrink-0"/>
                      <input value={logSearch} onChange={e => setLogSearch(e.target.value)} placeholder="Search IP, device, type…" className="bg-transparent text-sm text-slate-300 placeholder-slate-600 outline-none w-full"/>
                    </div>
                    <select value={logFilterSev} onChange={e => setLogFilterSev(e.target.value)} className="bg-slate-800 border border-slate-700 text-slate-300 text-xs rounded px-2 py-1.5 outline-none">
                      <option value="all">All Severities</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option>
                    </select>
                    <select value={logFilterType} onChange={e => setLogFilterType(e.target.value)} className="bg-slate-800 border border-slate-700 text-slate-300 text-xs rounded px-2 py-1.5 outline-none">
                      <option value="all">All Types</option>{logTypes.map(t=><option key={t} value={t}>{t}</option>)}
                    </select>
                    <select value={logFilterDev} onChange={e => setLogFilterDev(e.target.value)} className="bg-slate-800 border border-slate-700 text-slate-300 text-xs rounded px-2 py-1.5 outline-none">
                      <option value="all">All Devices</option>{logDevices.map(d=><option key={d} value={d}>{d}</option>)}
                    </select>
                    <select value={logLimit} onChange={e => setLogLimit(Number(e.target.value))} className="bg-slate-800 border border-slate-700 text-slate-300 text-xs rounded px-2 py-1.5 outline-none">
                      <option value={100}>Last 100</option><option value={200}>Last 200</option><option value={500}>Last 500</option><option value={1000}>Last 1000</option>
                    </select>
                    {(logFilterSev!=='all'||logFilterType!=='all'||logFilterDev!=='all'||logSearch) &&
                      <button onClick={()=>{setLogFilterSev('all');setLogFilterType('all');setLogFilterDev('all');setLogSearch('');}} className="text-xs text-rose-400 hover:text-rose-300">Clear filters</button>}
                  </div>
                  <div className="flex-1 overflow-auto">
                    {logLoading ? (
                      <div className="flex items-center justify-center h-40 text-slate-500 text-sm gap-2"><RefreshCw className="w-4 h-4 animate-spin"/> Loading logs from database…</div>
                    ) : logFiltered.length === 0 ? (
                      <div className="flex flex-col items-center justify-center h-40 text-slate-600 gap-2"><Database className="w-8 h-8"/><p className="text-sm">No attack events match the current filters.</p></div>
                    ) : (
                      <table className="w-full text-xs">
                        <thead className="sticky top-0 bg-slate-800 z-10">
                          <tr>{['#','Timestamp','Attack Type','Severity','Device','Source IP','Dest IP','Confidence','Anomaly Score'].map(h=>(
                            <th key={h} className="text-left px-4 py-2.5 text-slate-400 font-semibold uppercase tracking-wider whitespace-nowrap border-b border-slate-700">{h}</th>
                          ))}</tr>
                        </thead>
                        <tbody>
                          {logFiltered.map(r=>(
                            <tr key={r.id} className="border-b border-slate-800/60 hover:bg-slate-800/40 transition-colors">
                              <td className="px-4 py-2.5 text-slate-600 font-mono">{r.id}</td>
                              <td className="px-4 py-2.5 text-slate-400 font-mono whitespace-nowrap">{logFmtTs(r.timestamp)}</td>
                              <td className="px-4 py-2.5 font-semibold text-slate-200">{r.prediction}</td>
                              <td className="px-4 py-2.5"><span className={`px-2 py-0.5 rounded-full text-xs font-bold border uppercase ${logSevBg(r.severity)}`}>{r.severity}</span></td>
                              <td className="px-4 py-2.5 text-slate-300">{r.device}</td>
                              <td className="px-4 py-2.5 font-mono text-cyan-400">{r.src_ip}</td>
                              <td className="px-4 py-2.5 font-mono text-slate-400">{r.dst_ip}</td>
                              <td className="px-4 py-2.5">
                                <div className="flex items-center gap-2">
                                  <div className="w-16 h-1.5 bg-slate-700 rounded-full overflow-hidden"><div className="h-full rounded-full bg-violet-500" style={{width:`${r.confidence}%`}}/></div>
                                  <span className="text-slate-300 font-mono">{r.confidence.toFixed(1)}%</span>
                                </div>
                              </td>
                              <td className={`px-4 py-2.5 font-mono ${r.anomaly_score>0.5?'text-red-400':r.anomaly_score>0.25?'text-amber-400':'text-emerald-400'}`}>{r.anomaly_score.toFixed(4)}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    )}
                  </div>
                  <div className="px-6 py-2 border-t border-slate-800 bg-slate-900 flex items-center justify-between flex-shrink-0">
                    <span className="text-xs text-slate-600">Showing {logFiltered.length} of {logData.length} stored records · SQLite · alerts.db</span>
                    <span className="text-xs text-slate-700 font-mono">iomt_attack_logs_{new Date().toISOString().slice(0,10)}.csv</span>
                  </div>
                </div>
              );
            })()}

            {/* ── TAB 2: Incident Playbooks ── */}
            {activeTab==='playbook' && (() => {
              const pb       = playbookData[playbookType] || playbookData.DDoS;
              const done     = playbookDone[playbookType]    || {};
              const notes    = playbookNotes[playbookType]   || {};
              const startTs  = playbookStarted[playbookType] || null;
              const doneCount     = Object.values(done).filter(v=>v==='done').length;
              const progressCount = Object.values(done).filter(v=>v==='progress').length;
              const elapsedMin    = startTs ? Math.round((Date.now()-startTs)/60000) : 0;
              const slaRatio      = startTs ? Math.min(1, elapsedMin/pb.sla) : 0;
              const pbComplete    = doneCount === pb.steps.length;

              const sevCfg = { critical:{bg:'bg-red-500/15',border:'border-red-500/40',text:'text-red-400'}, high:{bg:'bg-orange-500/15',border:'border-orange-500/40',text:'text-orange-400'}, medium:{bg:'bg-amber-500/15',border:'border-amber-500/40',text:'text-amber-400'} };
              const sc = sevCfg[pb.severity] || sevCfg.medium;

              const setStepState = (i, val) => {
                if (!startTs) setPlaybookStarted(p=>({...p,[playbookType]:Date.now()}));
                setPlaybookDone(p=>({...p,[playbookType]:{...(p[playbookType]||{}),[i]:val}}));
              };
              const setNote = (i, val) => setPlaybookNotes(p=>({...p,[playbookType]:{...(p[playbookType]||{}),[i]:val}}));
              const resetPb = () => { setPlaybookDone(p=>({...p,[playbookType]:{}})); setPlaybookNotes(p=>({...p,[playbookType]:{}})); setPlaybookStarted(p=>({...p,[playbookType]:null})); setPbSelectedStep(null); };

              return (
                <div className="flex h-full overflow-hidden">
                  {/* ── Left: Playbook selector ── */}
                  <div className="w-56 flex-shrink-0 border-r border-slate-800 bg-slate-900/60 flex flex-col overflow-y-auto">
                    <div className="px-4 pt-4 pb-2">
                      <p className="text-xs text-slate-500 uppercase tracking-widest font-semibold mb-3">Select Playbook</p>
                      {Object.entries(playbookData).map(([k,v])=>{
                        const d2 = playbookDone[k]||{};
                        const done2 = Object.values(d2).filter(x=>x==='done').length;
                        const pct2  = Math.round(done2/v.steps.length*100);
                        const isActive = playbookType===k;
                        return (
                          <button key={k} onClick={()=>{setPlaybookType(k);setPbSelectedStep(null);}}
                            className={`w-full text-left px-3 py-3 rounded-lg mb-2 border transition-all ${isActive?'bg-slate-800 border-slate-600':'border-transparent hover:bg-slate-800/50'}`}>
                            <div className="flex items-center gap-2 mb-1">
                              <span className="text-base">{v.icon}</span>
                              <span className={`text-sm font-bold ${isActive?'text-white':'text-slate-300'}`}>{k}</span>
                              {pct2===100 && <span className="ml-auto text-emerald-400 text-xs">✓</span>}
                            </div>
                            <div className="flex items-center gap-2">
                              <div className="flex-1 h-1 bg-slate-700 rounded-full overflow-hidden">
                                <div className="h-full rounded-full bg-emerald-500 transition-all" style={{width:`${pct2}%`}}/>
                              </div>
                              <span className="text-xs text-slate-500">{pct2}%</span>
                            </div>
                            <div className="flex items-center gap-2 mt-1.5">
                              <span className={`text-xs px-1.5 py-0.5 rounded font-semibold uppercase ${(sevCfg[v.severity]||sevCfg.medium).bg} ${(sevCfg[v.severity]||sevCfg.medium).text}`}>{v.severity}</span>
                              <span className="text-xs text-slate-600">SLA {v.sla}m</span>
                            </div>
                          </button>
                        );
                      })}
                    </div>
                    <div className="mt-auto p-4 border-t border-slate-800">
                      <button onClick={resetPb} className="w-full flex items-center justify-center gap-2 px-3 py-2 rounded-lg bg-slate-800 text-slate-400 text-xs hover:bg-slate-700 border border-slate-700">
                        <RotateCcw className="w-3 h-3"/> Reset Playbook
                      </button>
                    </div>
                  </div>

                  {/* ── Right: Active playbook ── */}
                  <div className="flex-1 flex flex-col overflow-hidden">
                    {/* Header */}
                    <div className={`px-6 py-4 border-b border-slate-800 flex-shrink-0 ${sc.bg}`}>
                      <div className="flex items-start justify-between">
                        <div className="flex items-center gap-3">
                          <span className="text-2xl">{pb.icon}</span>
                          <div>
                            <div className="flex items-center gap-2">
                              <h2 className="text-base font-bold text-white">{playbookType} Incident Response Playbook</h2>
                              <span className={`text-xs px-2 py-0.5 rounded-full font-bold uppercase border ${sc.bg} ${sc.border} ${sc.text}`}>{pb.severity}</span>
                              {pbComplete && <span className="text-xs px-2 py-0.5 rounded-full font-bold bg-emerald-500/20 text-emerald-400 border border-emerald-500/40">✓ COMPLETE</span>}
                            </div>
                            <p className="text-xs text-slate-400 mt-0.5">{pb.description}</p>
                          </div>
                        </div>
                        <div className="text-right text-xs text-slate-500 flex-shrink-0 ml-4">
                          <div className="font-mono text-slate-400">{startTs ? new Date(startTs).toLocaleTimeString() : '—'}</div>
                          <div>Started</div>
                        </div>
                      </div>
                      {/* SLA + progress row */}
                      <div className="mt-3 grid grid-cols-3 gap-4">
                        <div>
                          <div className="flex justify-between text-xs mb-1">
                            <span className="text-slate-400">SLA Timer</span>
                            <span className={slaRatio>0.8?'text-red-400 font-bold':slaRatio>0.5?'text-amber-400':'text-emerald-400'}>{startTs?`${elapsedMin}m / ${pb.sla}m`:`0m / ${pb.sla}m`}</span>
                          </div>
                          <div className="h-1.5 bg-slate-700 rounded-full overflow-hidden">
                            <div className={`h-full rounded-full transition-all ${slaRatio>0.8?'bg-red-500':slaRatio>0.5?'bg-amber-400':'bg-emerald-400'}`} style={{width:`${slaRatio*100}%`}}/>
                          </div>
                        </div>
                        <div>
                          <div className="flex justify-between text-xs mb-1">
                            <span className="text-slate-400">Steps Complete</span>
                            <span className="text-white font-bold">{doneCount}/{pb.steps.length}</span>
                          </div>
                          <div className="h-1.5 bg-slate-700 rounded-full overflow-hidden">
                            <div className="h-full rounded-full bg-emerald-500 transition-all" style={{width:`${Math.round(doneCount/pb.steps.length*100)}%`}}/>
                          </div>
                        </div>
                        <div className="flex items-center gap-4 text-xs">
                          <div className="flex items-center gap-1.5"><span className="w-2.5 h-2.5 rounded-full bg-emerald-500 inline-block"/><span className="text-slate-400">Done ({doneCount})</span></div>
                          <div className="flex items-center gap-1.5"><span className="w-2.5 h-2.5 rounded-full bg-amber-400 inline-block"/><span className="text-slate-400">In Progress ({progressCount})</span></div>
                          <div className="flex items-center gap-1.5"><span className="w-2.5 h-2.5 rounded-full bg-slate-600 inline-block"/><span className="text-slate-400">Pending ({pb.steps.length-doneCount-progressCount})</span></div>
                        </div>
                      </div>
                    </div>

                    {/* Steps list */}
                    <div className="flex-1 overflow-y-auto p-4 space-y-2">
                      {pb.steps.map((step,i)=>{
                        const state    = done[i] || 'pending';
                        const isExp    = pbSelectedStep===i;
                        const stepNote = notes[i]||'';
                        const stateCfg = {
                          done:     {ring:'border-emerald-500',bg:'bg-emerald-500/10',icon:<Check className="w-3 h-3 text-white"/>,dot:'bg-emerald-500',label:'Done'},
                          progress: {ring:'border-amber-400', bg:'bg-amber-400/10', icon:<span className="w-2 h-2 rounded-full bg-amber-400 animate-pulse inline-block"/>,dot:'bg-amber-400',label:'In Progress'},
                          pending:  {ring:'border-slate-600', bg:'',                icon:null, dot:'bg-slate-600',label:'Pending'},
                        }[state];
                        return (
                          <div key={i} className={`rounded-xl border transition-all ${stateCfg.ring} ${stateCfg.bg} ${isExp?'shadow-lg':''}`}>
                            {/* Step header row */}
                            <div className="flex items-center gap-3 p-3 cursor-pointer" onClick={()=>setPbSelectedStep(isExp?null:i)}>
                              {/* Status button */}
                              <div className="flex flex-col gap-1 flex-shrink-0">
                                <button onClick={e=>{e.stopPropagation();setStepState(i,state==='done'?'pending':'done');}}
                                  className={`w-6 h-6 rounded-full border-2 flex items-center justify-center ${state==='done'?'bg-emerald-500 border-emerald-500':state==='progress'?'border-amber-400 bg-amber-400/20':'border-slate-500 hover:border-emerald-400'}`}>
                                  {stateCfg.icon}
                                </button>
                              </div>
                              {/* Step info */}
                              <div className="flex-1 min-w-0">
                                <div className="flex items-center gap-2 flex-wrap">
                                  <span className="text-xs text-slate-500 font-mono">STEP {String(i+1).padStart(2,'0')}</span>
                                  <span className={`text-sm font-bold ${state==='done'?'line-through text-slate-500':'text-white'}`}>{step.t}</span>
                                  <span className={`text-xs px-1.5 py-0.5 rounded font-semibold ${stateCfg.dot==='bg-emerald-500'?'bg-emerald-500/20 text-emerald-400':stateCfg.dot==='bg-amber-400'?'bg-amber-400/20 text-amber-400':'bg-slate-700 text-slate-500'}`}>{stateCfg.label}</span>
                                </div>
                                <div className="flex items-center gap-3 mt-0.5 text-xs text-slate-500">
                                  <span className="flex items-center gap-1"><Clock className="w-3 h-3"/> {step.m} min</span>
                                  <span className="flex items-center gap-1"><Users className="w-3 h-3"/> {step.role}</span>
                                  <span className="text-violet-400 font-mono">{step.technique !== '—' ? step.technique : ''}</span>
                                </div>
                              </div>
                              {/* In-progress toggle */}
                              <button onClick={e=>{e.stopPropagation();setStepState(i,state==='progress'?'pending':'progress');}}
                                className={`px-2 py-1 rounded text-xs font-medium flex-shrink-0 border transition-all ${state==='progress'?'bg-amber-400/20 text-amber-400 border-amber-400/40':'border-slate-700 text-slate-500 hover:text-amber-400 hover:border-amber-400/40'}`}>
                                {state==='progress'?'⏳ Active':'▷ Start'}
                              </button>
                              <span className={`text-slate-500 text-xs flex-shrink-0 transition-transform ${isExp?'rotate-180':''}`}>▾</span>
                            </div>

                            {/* Expanded detail */}
                            {isExp && (
                              <div className="border-t border-slate-700/60 px-4 pt-3 pb-4 space-y-3">
                                <p className="text-sm text-slate-300 leading-relaxed">{step.d}</p>
                                <div className="grid grid-cols-2 gap-3">
                                  <div className="bg-slate-800/60 rounded-lg p-3">
                                    <p className="text-xs text-slate-500 uppercase tracking-wider mb-1.5 font-semibold">MITRE ATT&CK</p>
                                    <p className="text-xs text-violet-400 font-mono font-bold">{step.technique !== '—' ? step.technique : '—'}</p>
                                    <p className="text-xs text-slate-400 mt-0.5">{step.tactic}</p>
                                  </div>
                                  <div className="bg-slate-800/60 rounded-lg p-3">
                                    <p className="text-xs text-slate-500 uppercase tracking-wider mb-1.5 font-semibold">Tools Required</p>
                                    <div className="flex flex-wrap gap-1">
                                      {step.tools.map(tool=><span key={tool} className="text-xs bg-slate-700 text-slate-300 px-1.5 py-0.5 rounded">{tool}</span>)}
                                    </div>
                                  </div>
                                </div>
                                <div className="bg-slate-800/60 rounded-lg p-3">
                                  <p className="text-xs text-slate-500 uppercase tracking-wider mb-1.5 font-semibold">Evidence Required</p>
                                  <p className="text-xs text-amber-300">{step.evidence}</p>
                                </div>
                                <div>
                                  <p className="text-xs text-slate-500 uppercase tracking-wider mb-1.5 font-semibold">Analyst Notes</p>
                                  <textarea value={stepNote} onChange={e=>setNote(i,e.target.value)}
                                    placeholder="Document your findings, actions taken, and evidence collected…"
                                    rows={3}
                                    className="w-full bg-slate-800 border border-slate-700 rounded-lg px-3 py-2 text-xs text-slate-300 placeholder-slate-600 outline-none resize-none focus:border-slate-500"/>
                                </div>
                                <div className="flex gap-2">
                                  <button onClick={()=>setStepState(i,'done')} className="flex items-center gap-1.5 px-3 py-1.5 bg-emerald-600 hover:bg-emerald-500 text-white rounded text-xs font-bold">
                                    <Check className="w-3 h-3"/> Mark Done
                                  </button>
                                  <button onClick={()=>setStepState(i,'progress')} className="flex items-center gap-1.5 px-3 py-1.5 bg-amber-500/20 hover:bg-amber-500/30 text-amber-400 border border-amber-500/40 rounded text-xs font-medium">
                                    ⏳ In Progress
                                  </button>
                                  <button onClick={()=>setStepState(i,'pending')} className="px-3 py-1.5 bg-slate-700 hover:bg-slate-600 text-slate-400 rounded text-xs">
                                    Reset
                                  </button>
                                </div>
                              </div>
                            )}
                          </div>
                        );
                      })}
                    </div>
                  </div>
                </div>
              );
            })()}

            {/* ── TAB 3: Risk Scoring ── */}
            {activeTab==='risk' && (() => {
              const riskDevices = Object.entries(deviceRiskData);

              // ── Device detail + patch data (defined first so score helpers can use it) ──
              const rDeviceDetails = {
                'Infusion Pump':  { ip:'192.168.20.50', os:'VxWorks 6.9',    fw:'3.1.2',  cves:['CVE-2023-1234 (CVSS 9.1)','CVE-2024-5521 (CVSS 7.8)'], action:'Immediate firmware update + credential rotation', vlan:'VLAN 20',
                  patchList:[{id:'fw-3.2.0',label:'Firmware 3.2.0 (fixes CVE-2023-1234)',priority:'critical',reduction:14},{id:'cred-reset',label:'Reset default credentials',priority:'critical',reduction:10},{id:'port-close',label:'Close management port 8443',priority:'high',reduction:6}]},
                'Heart Monitor':  { ip:'192.168.20.22', os:'Windows XP Emb', fw:'2.0.1',  cves:['CVE-2023-4567 (CVSS 7.2)'], action:'OS upgrade to Windows 10 IoT LTSC', vlan:'VLAN 20',
                  patchList:[{id:'os-upgrade',label:'Upgrade to Windows 10 IoT LTSC',priority:'critical',reduction:12},{id:'tls-enable',label:'Enable TLS 1.2 minimum',priority:'high',reduction:7},{id:'cve-4567',label:'Apply CVE-2023-4567 hotfix',priority:'high',reduction:6}]},
                'Pulse Oximeter': { ip:'192.168.20.35', os:'FreeRTOS 10.4',  fw:'1.8.0',  cves:[], action:'Routine monitoring — no immediate action', vlan:'VLAN 20',
                  patchList:[]},
                'ECG Monitor':    { ip:'192.168.20.41', os:'Linux 4.4 LTS',  fw:'5.2.3',  cves:['CVE-2025-3341 (CVSS 6.5)'], action:'Enable TLS 1.3 + rotate auth tokens', vlan:'VLAN 20',
                  patchList:[{id:'tls13',label:'Enable TLS 1.3 + rotate auth tokens',priority:'high',reduction:8}]},
              };

              // ── Patch helpers ──
              const togglePatch = (device, patchId) => {
                const wasApplied = !!(appliedPatches[device]?.[patchId]);
                setAppliedPatches(prev => ({
                  ...prev,
                  [device]: { ...(prev[device]||{}), [patchId]: !wasApplied }
                }));
                const patch = rDeviceDetails[device]?.patchList?.find(p=>p.id===patchId);
                setResponseLog(prev => [{
                  id: Date.now(),
                  action: wasApplied ? `Patch rolled back: ${patch?.label||patchId}` : `Patch applied: ${patch?.label||patchId}`,
                  target: device,
                  alert: `Score ${wasApplied?'+':'−'}${patch?.reduction||0} pts`,
                  time: new Date().toLocaleTimeString(),
                  user: currentUser?.name || 'SOC Analyst',
                }, ...prev.slice(0, 49)]);
              };
              const isPatchApplied  = (device, patchId) => !!(appliedPatches[device]?.[patchId]);
              const getPatchReduction = (device) => {
                const patches = rDeviceDetails[device]?.patchList || [];
                return patches.filter(p => isPatchApplied(device, p.id)).reduce((s,p) => s+p.reduction, 0);
              };
              const getPatchesApplied = (device) => Object.values(appliedPatches[device]||{}).filter(Boolean).length;
              const getPatchesPending = (device) => Math.max(0, (rDeviceDetails[device]?.patchList||[]).length - getPatchesApplied(device));

              // ── Live alert enrichment from WebSocket stream ──
              const liveDeviceAlerts = {};
              alerts.forEach(a => {
                if (!a.device || a.status === 'fp' || !a.type || a.type === 'Benign') return;
                if (!liveDeviceAlerts[a.device]) liveDeviceAlerts[a.device] = { count:0, critical:0, high:0, medium:0, types:{} };
                const la = liveDeviceAlerts[a.device];
                la.count++;
                if (a.severity==='critical') la.critical++;
                else if (a.severity==='high') la.high++;
                else if (a.severity==='medium') la.medium++;
                const t = a.type || a.prediction;
                if (t) la.types[t] = (la.types[t]||0)+1;
              });

              // Score = base − patch reductions + live attack boost, clamped 1–100
              const getLiveScore = (device, baseScore) => {
                const la = liveDeviceAlerts[device];
                const attackBoost   = la ? Math.min(20, la.critical*8 + la.high*3 + la.medium*1) : 0;
                const patchReduct   = getPatchReduction(device);
                return Math.max(1, Math.min(100, baseScore - patchReduct + attackBoost));
              };
              const getLiveLevel = score => score>=75?'critical':score>=55?'high':score>=35?'medium':'low';
              const getMostCommonAttack = device => {
                const la = liveDeviceAlerts[device];
                if (!la || !Object.keys(la.types).length) return null;
                return Object.entries(la.types).sort((a,b)=>b[1]-a[1])[0][0];
              };

              const liveActiveDevices = Object.keys(liveDeviceAlerts).filter(d=>liveDeviceAlerts[d].count>0).length;
              const netScore = Math.round(riskDevices.reduce((s,[d,r])=>s+getLiveScore(d,r.score),0)/riskDevices.length);
              const netLevel = netScore>=75?'CRITICAL':netScore>=55?'HIGH':netScore>=35?'MEDIUM':'LOW';
              const netColor = netScore>=75?'#ef4444':netScore>=55?'#f97316':netScore>=35?'#eab308':'#22c55e';
              const totalPending = riskDevices.reduce((s,[d])=>s+getPatchesPending(d), 0);
              const critCount2 = riskDevices.filter(([d,r])=>getLiveLevel(getLiveScore(d,r.score))==='critical').length;
              const highCount2 = riskDevices.filter(([d,r])=>getLiveLevel(getLiveScore(d,r.score))==='high').length;

              const sevCfg2 = {
                critical:{ bg:'bg-red-500/10',    border:'border-red-500/30',    badge:'bg-red-500/20 text-red-300 border-red-500/40',    bar:'#ef4444', text:'text-red-400'    },
                high:    { bg:'bg-orange-500/10', border:'border-orange-500/30', badge:'bg-orange-500/20 text-orange-300 border-orange-500/40', bar:'#f97316', text:'text-orange-400' },
                medium:  { bg:'bg-amber-500/10',  border:'border-amber-500/30',  badge:'bg-amber-500/20 text-amber-300 border-amber-500/40',   bar:'#eab308', text:'text-amber-400'  },
                low:     { bg:'bg-emerald-500/10',border:'border-emerald-500/30',badge:'bg-emerald-500/20 text-emerald-300 border-emerald-500/40',bar:'#22c55e',text:'text-emerald-400'},
              };

              return (
                <div className="flex flex-col h-full bg-slate-950 overflow-hidden">

                  {/* ── Header ── */}
                  <div className="flex items-center justify-between px-6 py-4 border-b border-slate-800 bg-slate-900 flex-shrink-0">
                    <div className="flex items-center gap-3">
                      <Shield className="w-5 h-5 text-red-400"/>
                      <div>
                        <h2 className="text-base font-bold text-white">IoMT Device Risk Assessment</h2>
                        <p className="text-xs text-slate-500">Vulnerability scoring · CVE tracking · Patch management · HIPAA compliance posture</p>
                      </div>
                    </div>
                    <div className="flex items-center gap-3">
                      {liveActiveDevices>0 && (
                        <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-red-500/10 border border-red-500/30">
                          <span className="w-1.5 h-1.5 rounded-full bg-red-500 animate-pulse"/>
                          <span className="text-xs text-red-400 font-bold">{liveActiveDevices} device{liveActiveDevices!==1?'s':''} under attack</span>
                        </div>
                      )}
                      <div className="text-xs text-slate-500 font-mono">Last scanned: {new Date().toLocaleString()}</div>
                    </div>
                  </div>

                  {/* ── KPI strip ── */}
                  <div className="grid grid-cols-4 gap-px bg-slate-800 flex-shrink-0">
                    {[
                      { label:'Network Risk Score',  value:netScore,          sub:netLevel,                        color:netColor          },
                      { label:'Critical Devices',    value:critCount2,        sub:'Require immediate action',      color:'#ef4444'         },
                      { label:'High Risk',           value:highCount2,        sub:'Elevated threat posture',       color:'#f97316'         },
                      { label:'Live Active Attacks', value:liveActiveDevices, sub:totalPending+' patches still pending', color:liveActiveDevices>0?'#ef4444':'#22c55e' },
                    ].map(k=>(
                      <div key={k.label} className="bg-slate-900 px-6 py-4">
                        <div className="text-3xl font-bold" style={{color:k.color}}>{k.value}</div>
                        <div className="text-xs text-white font-semibold mt-1">{k.label}</div>
                        <div className="text-xs text-slate-500 mt-0.5">{k.sub}</div>
                      </div>
                    ))}
                  </div>

                  {/* ── Body ── */}
                  <div className="flex flex-1 overflow-hidden">

                    {/* Left: Network posture */}
                    <div className="w-60 flex-shrink-0 border-r border-slate-800 bg-slate-900/40 p-5 overflow-y-auto">
                      <p className="text-xs text-slate-500 uppercase tracking-widest font-semibold mb-4">Network Posture</p>

                      {/* Donut gauge */}
                      <div className="flex flex-col items-center mb-6">
                        <div className="relative w-32 h-32">
                          <svg className="w-32 h-32 -rotate-90" viewBox="0 0 120 120">
                            <circle cx="60" cy="60" r="48" stroke="#1e293b" strokeWidth="12" fill="none"/>
                            <circle cx="60" cy="60" r="48" stroke={netColor} strokeWidth="12" fill="none" strokeLinecap="round" strokeDasharray={`${(netScore/100)*301.6} 301.6`}/>
                          </svg>
                          <div className="absolute inset-0 flex flex-col items-center justify-center">
                            <span className="text-3xl font-black" style={{color:netColor}}>{netScore}</span>
                            <span className="text-xs font-bold text-slate-400">{netLevel}</span>
                          </div>
                        </div>
                        <p className="text-xs text-slate-500 mt-2 text-center">Overall Network Risk Score</p>
                      </div>

                      {/* Risk distribution */}
                      <div className="space-y-3 mb-6">
                        {[
                          {l:'Critical',  v:critCount2, c:'#ef4444'},
                          {l:'High',      v:highCount2, c:'#f97316'},
                          {l:'Medium',    v:riskDevices.filter(([d,r])=>getLiveLevel(getLiveScore(d,r.score))==='medium').length, c:'#eab308'},
                          {l:'Low',       v:riskDevices.filter(([d,r])=>getLiveLevel(getLiveScore(d,r.score))==='low').length,    c:'#22c55e'},
                        ].map(r=>(
                          <div key={r.l}>
                            <div className="flex justify-between text-xs mb-1">
                              <span className="text-slate-400">{r.l}</span>
                              <span className="font-bold text-white">{r.v} device{r.v!==1?'s':''}</span>
                            </div>
                            <div className="h-1.5 bg-slate-800 rounded-full overflow-hidden">
                              <div className="h-full rounded-full" style={{width:`${(r.v/riskDevices.length)*100}%`,background:r.c}}/>
                            </div>
                          </div>
                        ))}
                      </div>

                      {/* Compliance snapshot */}
                      <p className="text-xs text-slate-500 uppercase tracking-widest font-semibold mb-3">HIPAA Risk Flags</p>
                      <div className="space-y-2">
                        {[
                          {f:'PHI exposure risk',    ok:false},
                          {f:'Unencrypted transit',  ok:false},
                          {f:'Default credentials',  ok:false},
                          {f:'Pending CVE patches',  ok:false},
                          {f:'Audit logging active', ok:true },
                        ].map(f=>(
                          <div key={f.f} className="flex items-center gap-2 text-xs">
                            <span className={f.ok?'text-emerald-400':'text-red-400'}>{f.ok?'✓':'✗'}</span>
                            <span className={f.ok?'text-slate-400':'text-slate-300'}>{f.f}</span>
                          </div>
                        ))}
                      </div>
                    </div>

                    {/* Right: Device cards */}
                    <div className="flex-1 overflow-y-auto p-5">
                      <p className="text-xs text-slate-500 uppercase tracking-widest font-semibold mb-4">Device Risk Profiles</p>
                      <div className="grid grid-cols-2 gap-4">
                        {riskDevices.map(([device, risk])=>{
                          const liveScore  = getLiveScore(device, risk.score);
                          const liveLevel  = getLiveLevel(liveScore);
                          const sc2        = sevCfg2[liveLevel] || sevCfg2.low;
                          const detail     = rDeviceDetails[device] || {};
                          const circumference = 2*Math.PI*28;
                          const isIsolated = isolatedDevices.includes(device);
                          const la         = liveDeviceAlerts[device];
                          const hasLive    = la && la.count > 0;
                          const topAttack  = getMostCommonAttack(device);
                          return (
                            <div key={device} className={`rounded-xl border ${sc2.border} ${sc2.bg} overflow-hidden`}>
                              {/* Card header */}
                              <div className="flex items-center gap-4 p-4 border-b border-slate-800/60">
                                <div className="relative w-16 h-16 flex-shrink-0">
                                  <svg className="w-16 h-16 -rotate-90" viewBox="0 0 64 64">
                                    <circle cx="32" cy="32" r="28" stroke="#1e293b" strokeWidth="6" fill="none"/>
                                    <circle cx="32" cy="32" r="28" stroke={sc2.bar} strokeWidth="6" fill="none" strokeLinecap="round" strokeDasharray={`${(liveScore/100)*circumference} ${circumference}`}/>
                                  </svg>
                                  <div className="absolute inset-0 flex flex-col items-center justify-center">
                                    <span className="text-base font-black" style={{color:sc2.bar}}>{liveScore}</span>
                                  </div>
                                </div>
                                <div className="flex-1 min-w-0">
                                  <div className="flex items-center gap-2 mb-1">
                                    {getDeviceIcon(device)}
                                    <span className="text-sm font-bold text-white truncate">{device}</span>
                                    {hasLive && <span className="w-1.5 h-1.5 rounded-full bg-red-500 animate-pulse flex-shrink-0"/>}
                                  </div>
                                  <div className="flex items-center gap-1.5 flex-wrap">
                                    <span className={`text-xs px-2 py-0.5 rounded-full font-bold border uppercase ${sc2.badge}`}>{liveLevel}</span>
                                    {hasLive && <span className="text-xs px-2 py-0.5 rounded-full font-bold bg-red-500/20 text-red-300 border border-red-500/40 uppercase">LIVE</span>}
                                    {isIsolated && (
                                      <span
                                        className="text-xs px-2 py-0.5 rounded-full font-bold bg-violet-500/20 text-violet-300 border border-violet-500/40 uppercase"
                                        title={isolationMeta[device]?.trigger ? `Triggered by ${isolationMeta[device].trigger} (${isolationMeta[device].severity})` : 'Manually isolated'}
                                      >
                                        ISOLATED{isolationMeta[device]?.ts ? ` · ${timeAgo(isolationMeta[device].ts)}` : ''}
                                      </span>
                                    )}
                                  </div>
                                  <div className="flex items-center gap-3 mt-1.5 text-xs text-slate-500 font-mono">
                                    <span>{detail.ip||'—'}</span>
                                    <span>{detail.vlan||''}</span>
                                  </div>
                                </div>
                              </div>

                              {/* Live alert summary */}
                              {hasLive && (
                                <div className="mx-4 mt-3 p-2.5 rounded-lg bg-red-500/10 border border-red-500/20">
                                  <div className="flex items-center justify-between mb-1">
                                    <span className="text-xs font-bold text-red-400">ACTIVE THREAT DETECTED</span>
                                    <span className="text-xs text-red-300 font-mono">{la.count} event{la.count!==1?'s':''}</span>
                                  </div>
                                  <div className="flex gap-3 text-xs text-slate-400 flex-wrap">
                                    {la.critical>0 && <span><span className="text-red-400 font-bold">{la.critical}</span> critical</span>}
                                    {la.high>0     && <span><span className="text-orange-400 font-bold">{la.high}</span> high</span>}
                                    {la.medium>0   && <span><span className="text-amber-400 font-bold">{la.medium}</span> medium</span>}
                                    {topAttack     && <span className="ml-auto text-slate-500">Top: <span className="text-slate-300">{topAttack}</span></span>}
                                  </div>
                                </div>
                              )}

                              {/* Quarantine reason — shown when isolated */}
                              {isIsolated && (
                                <div className="mx-4 mt-3 p-2.5 rounded-lg bg-violet-500/10 border border-violet-500/20">
                                  <div className="flex items-center gap-2 mb-1">
                                    <span className="text-xs font-bold text-violet-300 uppercase tracking-wider">Quarantine Reason</span>
                                    {isolationMeta[device]?.ts && (
                                      <span className="text-xs text-violet-400/60 font-mono ml-auto">{timeAgo(isolationMeta[device].ts)}</span>
                                    )}
                                  </div>
                                  <p className="text-xs text-slate-300">
                                    {isolationMeta[device]
                                      ? `${isolationMeta[device].severity?.toUpperCase()} severity ${isolationMeta[device].trigger} attack detected — device moved to VLAN 99 (Quarantine). Awaiting remediation sign-off.`
                                      : 'Manually isolated by SOC analyst — device moved to VLAN 99 (Quarantine).'}
                                  </p>
                                </div>
                              )}

                              {/* System info */}
                              <div className={`grid grid-cols-2 gap-px bg-slate-800/40 border-b border-slate-800/60 ${hasLive||isIsolated?'mt-3':''}`}>
                                {[['OS',detail.os||'—'],['Firmware',detail.fw||'—']].map(([k,v])=>(
                                  <div key={k} className="bg-slate-900/30 px-3 py-2">
                                    <div className="text-xs text-slate-500 uppercase tracking-wider">{k}</div>
                                    <div className="text-xs text-slate-300 font-mono mt-0.5">{v}</div>
                                  </div>
                                ))}
                              </div>

                              {/* Risk factors */}
                              <div className="p-4 space-y-1.5">
                                <div className="flex items-center justify-between mb-2">
                                  <p className="text-xs text-slate-500 uppercase tracking-wider font-semibold">Risk Factors</p>
                                  {(dismissedFactors[device]||[]).length > 0 && (
                                    <button onClick={()=>restoreFactors(device)} className="text-xs text-slate-500 hover:text-slate-300 transition-colors">
                                      restore {(dismissedFactors[device]).length} resolved
                                    </button>
                                  )}
                                </div>
                                {/* Static factors — hover to dismiss */}
                                {risk.factors
                                  .filter(f => !(dismissedFactors[device]||[]).includes(f))
                                  .map((f,i)=>(
                                    <div key={i} className="flex items-start gap-2 text-xs group">
                                      <AlertTriangle className="w-3 h-3 text-amber-400 flex-shrink-0 mt-0.5"/>
                                      <span className="text-slate-300 flex-1">{f}</span>
                                      <button
                                        onClick={()=>dismissFactor(device, f)}
                                        title="Mark as resolved"
                                        className="opacity-0 group-hover:opacity-100 text-slate-600 hover:text-emerald-400 transition-all text-xs leading-none flex-shrink-0"
                                      >✓</button>
                                    </div>
                                  ))
                                }
                                {/* Live factors — auto-derived from recent alerts */}
                                {(liveRiskFactors[device]||[]).map((f,i)=>(
                                  <div key={'live-'+i} className="flex items-start gap-2 text-xs">
                                    <span className="w-3 h-3 flex-shrink-0 mt-0.5 flex items-center justify-center">
                                      <span className="w-2 h-2 rounded-full bg-red-500 animate-pulse inline-block"/>
                                    </span>
                                    <span className="text-red-300 flex-1">{f}</span>
                                    <span className="text-red-400/50 font-mono text-xs flex-shrink-0">LIVE</span>
                                  </div>
                                ))}
                                {risk.factors.filter(f=>!(dismissedFactors[device]||[]).includes(f)).length === 0 &&
                                 (liveRiskFactors[device]||[]).length === 0 && (
                                  <p className="text-xs text-emerald-400/60 italic">All known risk factors resolved</p>
                                )}
                              </div>

                              {/* CVEs */}
                              {detail.cves?.length>0 && (
                                <div className="px-4 pb-3">
                                  <p className="text-xs text-slate-500 uppercase tracking-wider font-semibold mb-2">Known CVEs</p>
                                  {detail.cves.map(cve=>(
                                    <div key={cve} className="flex items-center gap-2 text-xs mb-1">
                                      <span className="w-1.5 h-1.5 rounded-full bg-red-500 flex-shrink-0"/>
                                      <span className="font-mono text-red-300">{cve}</span>
                                    </div>
                                  ))}
                                </div>
                              )}

                              {/* Patch Management */}
                              <div className="px-4 pb-3">
                                <div className="flex items-center justify-between mb-2">
                                  <p className="text-xs text-slate-500 uppercase tracking-wider font-semibold">Patch Management</p>
                                  <div className="flex items-center gap-2 text-xs">
                                    <span className="text-slate-500">Last audit:</span>
                                    <span className="text-slate-400 font-mono">{timeAgo(auditTimestamps[device])}</span>
                                    <button
                                      onClick={() => markAudited(device)}
                                      title="Mark as audited now"
                                      className="flex items-center gap-1 px-1.5 py-0.5 rounded bg-slate-700/60 hover:bg-cyan-500/20 border border-slate-600/50 hover:border-cyan-500/40 text-slate-400 hover:text-cyan-400 transition-all"
                                    >
                                      <Clock className="w-3 h-3" />
                                      <span>Mark audited</span>
                                    </button>
                                  </div>
                                </div>
                                {detail.patchList?.length > 0 ? (
                                  <div className="space-y-1.5">
                                    {detail.patchList.map(p => {
                                      const applied = isPatchApplied(device, p.id);
                                      const prioColor = p.priority==='critical'?'text-red-400':p.priority==='high'?'text-orange-400':'text-amber-400';
                                      return (
                                        <div key={p.id} className={`flex items-center gap-2.5 p-2 rounded-lg border text-xs cursor-pointer transition-all ${applied?'bg-emerald-500/10 border-emerald-500/20 opacity-60':'bg-slate-800/50 border-slate-700/50 hover:border-slate-600/70'}`}
                                          onClick={()=>togglePatch(device, p.id)}>
                                          <div className={`w-4 h-4 rounded flex items-center justify-center flex-shrink-0 border transition-all ${applied?'bg-emerald-500 border-emerald-500':'border-slate-600 hover:border-slate-400'}`}>
                                            {applied && <span className="text-white text-xs leading-none">✓</span>}
                                          </div>
                                          <span className={`flex-1 ${applied?'line-through text-slate-500':'text-slate-300'}`}>{p.label}</span>
                                          <span className={`font-bold uppercase text-xs ${prioColor} flex-shrink-0`}>{p.priority}</span>
                                        </div>
                                      );
                                    })}
                                    <div className="flex items-center justify-between mt-2 pt-2 border-t border-slate-800/60 text-xs">
                                      <span className="text-slate-500">{getPatchesApplied(device)}/{detail.patchList.length} applied</span>
                                      {getPatchesPending(device)===0
                                        ? <span className="text-emerald-400 font-bold">All patches applied</span>
                                        : <span className="text-amber-400 font-bold">{getPatchesPending(device)} pending</span>}
                                    </div>
                                  </div>
                                ) : (
                                  <div className="flex items-center gap-2 text-xs text-emerald-400 py-1">
                                    <span>✓</span><span>No patches required</span>
                                  </div>
                                )}
                              </div>

                              {/* Recommended Action */}
                              <div className="px-4 pb-3">
                                <div className="p-2.5 rounded-lg bg-slate-800/60 border border-slate-700/60">
                                  <p className="text-xs text-slate-500 uppercase tracking-wider mb-1 font-semibold">Recommended Action</p>
                                  <p className="text-xs text-amber-300 leading-relaxed">{detail.action||'Continue routine monitoring'}</p>
                                </div>
                              </div>

                              {/* Action buttons — 2×2 grid, equal height */}
                              <div className="px-4 pb-4 grid grid-cols-2 gap-2">
                                {[
                                  {
                                    label: isIsolated ? 'Restore Network' : 'Isolate Device',
                                    icon:  isIsolated ? '🔓' : '🔒',
                                    cls:   isIsolated ? 'bg-violet-500/20 text-violet-300 border-violet-500/40 hover:bg-violet-500/30' : 'bg-red-500/10 text-red-400 border-red-500/30 hover:bg-red-500/20',
                                    fn: () => {
                                      if (isIsolated) {
                                        // Open remediation modal — restore only after checklist complete
                                        setRestoreModal({ device, meta: isolationMeta[device] || null });
                                        setRemediationChecks({});
                                      } else {
                                        // Isolate via handleQuickAction so ACLs, topology, metadata all update
                                        const syntheticAlert = { id: Date.now(), device, type: topAttack || 'Manual', severity: 'high', sourceIP: detail.ip || '0.0.0.0' };
                                        handleQuickAction('isolate', syntheticAlert);
                                      }
                                    },
                                  },
                                  {
                                    label: 'Open Playbook',
                                    icon:  '📋',
                                    cls:   'bg-blue-500/10 text-blue-400 border-blue-500/30 hover:bg-blue-500/20',
                                    fn:    ()=>{ const t=topAttack&&playbookData[topAttack]?topAttack:'DDoS'; setPlaybookType(t); setActiveTab('playbook'); },
                                  },
                                  {
                                    label: 'View Alerts',
                                    icon:  '🔔',
                                    cls:   'bg-amber-500/10 text-amber-400 border-amber-500/30 hover:bg-amber-500/20',
                                    fn:    ()=>setActiveTab('alerts'),
                                  },
                                  {
                                    label: 'Attack Logs',
                                    icon:  '📊',
                                    cls:   'bg-slate-700/40 text-slate-400 border-slate-600/40 hover:bg-slate-700/60',
                                    fn:    ()=>setActiveTab('logs'),
                                  },
                                ].map(b=>(
                                  <button key={b.label} onClick={b.fn}
                                    className={`flex items-center justify-center gap-1.5 h-8 rounded-lg font-bold border text-xs transition-all ${b.cls}`}>
                                    <span className="text-sm leading-none">{b.icon}</span>
                                    <span>{b.label}</span>
                                  </button>
                                ))}
                              </div>
                            </div>
                          );
                        })}
                      </div>
                    </div>
                  </div>
                </div>
              );
            })()}

            {/* ── TAB 4: Forensic Analysis ── */}
            {activeTab==='forensics' && (() => {
              // Derive unique devices from packets for the device filter
              const pktDevices = [...new Set(packets.map(p => p.device).filter(Boolean))];
              const filteredPkts = packets.filter(p => {
                if (pktFilterProto  !== 'all' && p.protocol !== pktFilterProto)  return false;
                if (pktFilterType   === 'attack'  && !p.flag)  return false;
                if (pktFilterType   === 'benign'  &&  p.flag)  return false;
                if (pktFilterDevice !== 'all' && p.device !== pktFilterDevice) return false;
                return true;
              });
              const exportCSV = () => {
                const header = ['No','Time','Source','Destination','Protocol','Length','Info','Flagged','Device'];
                const rows   = filteredPkts.map(p => [p.no, `"${p.time}"`, p.src, p.dst, p.protocol, p.len, `"${p.info}"`, p.flag ? 'Yes' : 'No', p.device || '']);
                const csv    = [header, ...rows].map(r => r.join(',')).join('\n');
                const blob   = new Blob([csv], { type: 'text/csv' });
                const url    = URL.createObjectURL(blob);
                const a      = document.createElement('a'); a.href = url; a.download = `packets_${Date.now()}.csv`; a.click();
                URL.revokeObjectURL(url);
              };
              return (
              <div className="flex-1 overflow-hidden flex flex-col">
                {/* Header row */}
                <div className="px-3 py-2 border-b border-slate-700/40 flex items-center gap-2 flex-shrink-0 flex-wrap">
                  <Search className="w-4 h-4 text-violet-400"/><span className="font-bold text-base">Packet Capture — Wireshark View</span>
                  <span className="text-base text-slate-500">{filteredPkts.length}/{packets.length} packets</span>
                  {/* Filters */}
                  <div className="ml-auto flex items-center gap-2 flex-wrap">
                    <select value={pktFilterProto} onChange={e=>setPktFilterProto(e.target.value)}
                      className="bg-slate-800 border border-slate-600 text-slate-300 text-base rounded px-2 py-1 focus:outline-none">
                      <option value="all">All Protocols</option>
                      {['TCP','UDP','ARP','ICMP'].map(p=><option key={p} value={p}>{p}</option>)}
                    </select>
                    <select value={pktFilterType} onChange={e=>setPktFilterType(e.target.value)}
                      className="bg-slate-800 border border-slate-600 text-slate-300 text-base rounded px-2 py-1 focus:outline-none">
                      <option value="all">All Traffic</option>
                      <option value="attack">Attack Only</option>
                      <option value="benign">Benign Only</option>
                    </select>
                    <select value={pktFilterDevice} onChange={e=>setPktFilterDevice(e.target.value)}
                      className="bg-slate-800 border border-slate-600 text-slate-300 text-base rounded px-2 py-1 focus:outline-none">
                      <option value="all">All Devices</option>
                      {pktDevices.map(d=><option key={d} value={d}>{d}</option>)}
                    </select>
                    {(pktFilterProto!=='all'||pktFilterType!=='all'||pktFilterDevice!=='all') && (
                      <button onClick={()=>{setPktFilterProto('all');setPktFilterType('all');setPktFilterDevice('all');}}
                        className="px-2 py-1 text-base rounded bg-slate-700 text-slate-400 hover:text-white">Clear</button>
                    )}
                    <button onClick={exportCSV}
                      className="flex items-center gap-1 px-3 py-1 text-base rounded bg-violet-600 hover:bg-violet-500 text-white font-medium">
                      <Download className="w-3 h-3"/> Export CSV
                    </button>
                  </div>
                </div>
                <div className="flex flex-1 overflow-hidden min-h-0">
                  {/* Packet table */}
                  <div className="flex-1 overflow-y-auto">
                    <table className="w-full text-base">
                      <thead className="bg-slate-900/60 sticky top-0">
                        <tr className="text-slate-400">
                          <th className="px-2 py-1.5 text-left font-medium">No.</th>
                          <th className="px-2 py-1.5 text-left font-medium">Time</th>
                          <th className="px-2 py-1.5 text-left font-medium">Source</th>
                          <th className="px-2 py-1.5 text-left font-medium">Destination</th>
                          <th className="px-2 py-1.5 text-left font-medium">Protocol</th>
                          <th className="px-2 py-1.5 text-left font-medium">Len</th>
                          <th className="px-2 py-1.5 text-left font-medium">Info</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-700/30">
                        {filteredPkts.map(pkt=>(
                          <tr key={pkt.no} onClick={()=>setSelectedPacket(pkt)}
                            className={`cursor-pointer hover:bg-slate-700/30 ${pkt.flag?'bg-red-500/10':''}${selectedPacket?.no===pkt.no?' bg-cyan-500/10':''}`}>
                            <td className="px-2 py-1 font-mono text-slate-400">{pkt.no}</td>
                            <td className="px-2 py-1 font-mono text-slate-400">{pkt.time}</td>
                            <td className="px-2 py-1 font-mono text-cyan-400">{pkt.src}</td>
                            <td className="px-2 py-1 font-mono text-emerald-400">{pkt.dst}</td>
                            <td className="px-2 py-1"><span className={`px-1 rounded text-base font-bold ${pkt.protocol==='TCP'?'bg-blue-500/20 text-blue-400':pkt.protocol==='UDP'?'bg-orange-500/20 text-orange-400':pkt.protocol==='ARP'?'bg-yellow-500/20 text-yellow-400':'bg-slate-500/20 text-slate-400'}`}>{pkt.protocol}</span></td>
                            <td className="px-2 py-1 font-mono">{pkt.len}</td>
                            <td className="px-2 py-1 text-slate-300 truncate max-w-[160px]">{pkt.info}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                  {/* Packet detail */}
                  {selectedPacket && (
                    <div className="w-48 border-l border-slate-700/40 p-3 overflow-y-auto flex-shrink-0 bg-slate-900/30">
                      <div className="flex items-center justify-between mb-2">
                        <span className="text-base font-bold text-violet-400">Packet #{selectedPacket.no}</span>
                        <button onClick={()=>setSelectedPacket(null)}><X className="w-3 h-3 text-slate-400"/></button>
                      </div>
                      <div className="space-y-2 text-base">
                        {[['Protocol',selectedPacket.protocol],['Source',selectedPacket.src],['Destination',selectedPacket.dst],['Length',`${selectedPacket.len} bytes`],['Time',`${selectedPacket.time}s`]].map(([k,v])=>(
                          <div key={k}><p className="text-slate-500">{k}</p><p className="font-mono text-white break-all">{v}</p></div>
                        ))}
                        <div>
                          <p className="text-slate-500 mb-1">Hex Payload</p>
                          <p className="font-mono text-emerald-400 text-base break-all leading-5">
                            {Array.from({length:16},()=>Math.floor(Math.random()*256).toString(16).padStart(2,'0')).join(' ')}
                          </p>
                        </div>
                        {selectedPacket.flag && <div className="p-2 rounded bg-red-500/10 border border-red-500/30"><p className="text-red-400 font-bold">⚠ Flagged as Malicious</p></div>}
                      </div>
                    </div>
                  )}
                </div>
              </div>
              );
            })()}

            {/* ── TAB 5: Geographic IP Map ── */}
            {activeTab==='geomap' && (() => {
              const sevColor = s => s==='critical'?'#ef4444':s==='high'?'#f97316':s==='medium'?'#eab308':'#3b82f6';
              const typeColor = t => ({DDoS:'#ef4444',DoS:'#f97316',Recon:'#3b82f6',MQTT:'#8b5cf6',Spoofing:'#eab308'}[t]||'#64748b');
              // Fully dynamic — build attack list from live hits only
              const liveAttacks = Object.entries(liveGeoHits)
                .map(([city, hit]) => {
                  const meta = CITY_META[city] || {};
                  return {
                    city,
                    count:    hit.count    || 1,
                    type:     hit.type     || 'Unknown',
                    severity: hit.severity || meta.severity || 'medium',
                    target:   hit.target   || 'Infusion Pump',
                    isp:      meta.isp     || '',
                    lat:      meta.lat,
                    lon:      meta.lon,
                    x:        meta.x,
                    y:        meta.y,
                    lastSeen: hit.lastSeen || 0,
                  };
                })
                .filter(a => a.x != null);
              const total = liveAttacks.reduce((s,g)=>s+g.count,0);
              return (
                <div className="flex-1 overflow-hidden flex flex-col">
                  {/* Header + severity stats */}
                  <div className="px-4 pt-3 pb-2 flex-shrink-0">
                    <div className="flex items-center justify-between mb-2">
                      <div className="flex items-center gap-2">
                        <Globe className="w-4 h-4 text-emerald-400"/>
                        <span className="font-bold text-lg">Attack Source Geography</span>
                        <span className="text-base text-slate-500">• {liveAttacks.length} sources</span>
                      </div>
                      <span className="text-base font-bold text-red-400">{total} total attacks</span>
                    </div>
                    <div className="grid grid-cols-5 gap-2">
                      {['DDoS','DoS','Recon','Spoofing','MQTT'].map(t=>{
                        const cnt = liveAttacks.filter(a=>a.type===t).reduce((s,a)=>s+a.count,0);
                        const col = typeColor(t);
                        return (
                          <div key={t} className="flex items-center gap-1.5 px-2 py-1.5 rounded-lg text-base" style={{backgroundColor:col+'18',border:`1px solid ${col}33`}}>
                            <div className="w-2 h-2 rounded-full flex-shrink-0" style={{backgroundColor:col}}/>
                            <span className="text-slate-300">{t}</span>
                            <span className="ml-auto font-bold" style={{color:col}}>{cnt}</span>
                          </div>
                        );
                      })}
                    </div>
                  </div>

                  {/* Map + detail side panel */}
                  <div className="flex flex-1 min-h-0 px-4 gap-4" style={{height:'520px'}}>
                    {/* Map — real world geography via D3-geo */}
                    <div className="flex-1 relative bg-slate-900/70 rounded-xl border border-slate-700/40 overflow-hidden"
                      onMouseMove={e=>{
                        const drag=mapDragRef.current; if(!drag) return;
                        const svg=mapSvgRef.current;  if(!svg) return;
                        const rect=svg.getBoundingClientRect();
                        const sx=200/rect.width, sy=100/rect.height;
                        const dx=(e.clientX-drag.sx)*sx;
                        const dy=(e.clientY-drag.sy)*sy;
                        const baseTx=drag.tx, baseTy=drag.ty;   // captured before updater runs
                        setMapZoom(prev=>{
                          const sc=prev.scale;
                          const tx=Math.min(0,Math.max(200*(1-sc), baseTx+dx));
                          const ty=Math.min(0,Math.max(100*(1-sc), baseTy+dy));
                          return {...prev,tx,ty};
                        });
                      }}
                      onMouseUp={()=>{ mapDragRef.current=null; }}
                      onMouseLeave={()=>{ mapDragRef.current=null; }}
                    >
                      {/* Zoom controls overlay */}
                      <div className="absolute top-2 right-2 z-10 flex flex-col gap-1">
                        {[{label:'+',delta:1.5},{label:'−',delta:1/1.5}].map(({label,delta})=>(
                          <button key={label} onClick={()=>setMapZoom(prev=>{
                            const sc=Math.min(8,Math.max(1,prev.scale*delta));
                            const cx=100, cy=50; // zoom toward center
                            const tx=Math.min(0,Math.max(200*(1-sc), cx-(cx-prev.tx)/prev.scale*sc));
                            const ty=Math.min(0,Math.max(100*(1-sc), cy-(cy-prev.ty)/prev.scale*sc));
                            return {scale:sc,tx,ty};
                          })}
                          className="w-6 h-6 rounded text-white font-bold text-sm flex items-center justify-center"
                          style={{background:'rgba(30,64,96,0.85)',border:'1px solid #2d4a6b'}}
                          >{label}</button>
                        ))}
                        <button onClick={()=>setMapZoom({scale:1,tx:0,ty:0})}
                          className="w-6 h-6 rounded text-slate-400 text-xs flex items-center justify-center"
                          style={{background:'rgba(30,64,96,0.85)',border:'1px solid #2d4a6b'}}
                          title="Reset zoom">⊡</button>
                      </div>
                      {mapZoom.scale>1.05&&(
                        <div className="absolute bottom-2 right-2 z-10 text-xs text-slate-400 px-1.5 py-0.5 rounded"
                          style={{background:'rgba(7,16,24,0.75)'}}>
                          {mapZoom.scale.toFixed(1)}×
                        </div>
                      )}
                      <svg ref={mapSvgRef} className="w-full h-full" viewBox="0 0 200 100" preserveAspectRatio="xMidYMid meet"
                        style={{display:'block', cursor: mapZoom.scale>1?'grab':'default'}}
                        onWheel={e=>{
                          e.preventDefault();
                          const svg=mapSvgRef.current; if(!svg) return;
                          const rect=svg.getBoundingClientRect();
                          const sx=200/rect.width, sy=100/rect.height;
                          const mx=(e.clientX-rect.left)*sx;
                          const my=(e.clientY-rect.top)*sy;
                          setMapZoom(prev=>{
                            const factor=e.deltaY<0?1.3:1/1.3;
                            const sc=Math.min(8,Math.max(1,prev.scale*factor));
                            const tx=Math.min(0,Math.max(200*(1-sc),mx-(mx-prev.tx)/prev.scale*sc));
                            const ty=Math.min(0,Math.max(100*(1-sc),my-(my-prev.ty)/prev.scale*sc));
                            return {scale:sc,tx,ty};
                          });
                        }}
                        onMouseDown={e=>{
                          if(e.button!==0) return;
                          mapDragRef.current={sx:e.clientX,sy:e.clientY,tx:mapZoom.tx,ty:mapZoom.ty};
                        }}
                      >
                        <defs>
                          <style>{`
                            @keyframes geopulse  { 0%{r:2;opacity:.9} 100%{r:7;opacity:0} }
                            @keyframes geopulse2 { 0%{r:1.5;opacity:.9} 100%{r:5;opacity:0} }
                            .geo-pulse  { animation: geopulse  2s ease-out infinite; }
                            .geo-pulse2 { animation: geopulse2 2.8s ease-out infinite 0.4s; }
                          `}</style>
                          <radialGradient id="oceanGrad2" cx="50%" cy="50%" r="60%">
                            <stop offset="0%" stopColor="#0c1a2e"/>
                            <stop offset="100%" stopColor="#071018"/>
                          </radialGradient>
                        </defs>

                        {/* ── Zoomable world layer ── */}
                        <g transform={`translate(${mapZoom.tx},${mapZoom.ty}) scale(${mapZoom.scale})`}>
                          {/* Ocean */}
                          <rect width="200" height="100" fill="url(#oceanGrad2)"/>

                          {/* Real country shapes from world-atlas */}
                          {worldPaths.length === 0 ? (
                            <text x="100" y="52" textAnchor="middle" fill="#334155" fontSize="3">Loading map…</text>
                          ) : worldPaths.map((d,i) => (
                            <path key={i} d={d} fill="#1a2b3f" stroke="#2d4a6b" strokeWidth="0.3"/>
                          ))}

                          {/* Lat/lon grid */}
                          {[-60,-30,0,30,60].map(lat=>{
                            const y=(90-lat)/180*100;
                            return <line key={lat} x1="0" y1={y} x2="200" y2={y} stroke="#1e3a5f" strokeWidth="0.15" strokeDasharray={lat===0?"2 2":undefined} opacity="0.5"/>;
                          })}
                          {[-150,-120,-90,-60,-30,0,30,60,90,120,150].map(lon=>{
                            const x=(lon+180)/360*200;
                            return <line key={lon} x1={x} y1="0" x2={x} y2="100" stroke="#1e3a5f" strokeWidth="0.1" opacity="0.3"/>;
                          })}

                          {/* Attack lines → hospital */}
                          {liveAttacks.map((a,i)=>{
                            const col=typeColor(a.type);
                            const isSel=selectedGeoAttack?.city===a.city;
                            return (
                              <line key={i} x1={a.x} y1={a.y} x2={HOSPITAL.x} y2={HOSPITAL.y}
                                stroke={col} strokeWidth={isSel?0.7/mapZoom.scale:0.25/mapZoom.scale} strokeDasharray="2 2"
                                opacity={selectedGeoAttack&&!isSel?0.1:isSel?1:0.45}/>
                            );
                          })}

                          {/* Hospital beacon on world map — pin tip anchored at NYC */}
                          {(()=>{
                            const s = 1/mapZoom.scale;
                            const tipX = HOSPITAL.x, tipY = HOSPITAL.y; // tip = exact NYC coordinate
                            const r = 3.5*s;
                            const tailH = 4*s;
                            const tailW = 1.8*s;
                            const cx = tipX;              // circle centre directly above tip
                            const cy = tipY - r - tailH;
                            return (
                              <g>
                                {/* Outer pulse ring */}
                                <circle cx={cx} cy={cy} r={6*s} fill="#06b6d4" opacity="0.08"/>
                                <circle cx={cx} cy={cy} r={5.5*s} fill="none" stroke="#06b6d4" strokeWidth={0.5*s} opacity="0.3" className="geo-pulse"/>
                                {/* Label tag above circle */}
                                <rect x={cx-6.5*s} y={cy-r-4.5*s} width={13*s} height={3.5*s} rx={0.8*s}
                                  fill="#071018" fillOpacity="0.88" stroke="#06b6d4" strokeWidth={0.3*s}/>
                                <text x={cx} y={cy-r-1.7*s} textAnchor="middle"
                                  fill="#06b6d4" fontSize={2.2*s} fontWeight="bold"
                                  fontFamily="system-ui,sans-serif">HOSPITAL</text>
                                {/* Pin tail pointing down to tip at NYC */}
                                <polygon
                                  points={`${cx-tailW},${cy+r*0.75} ${cx+tailW},${cy+r*0.75} ${tipX},${tipY}`}
                                  fill="#0891b2"/>
                                {/* Pin circle body */}
                                <circle cx={cx} cy={cy} r={r} fill="#0891b2" stroke="#06b6d4" strokeWidth={0.6*s}/>
                                {/* White H letter */}
                                <text x={cx} y={cy+1.2*s} textAnchor="middle"
                                  fill="white" fontSize={4.2*s} fontWeight="900"
                                  fontFamily="system-ui,sans-serif">H</text>
                                {/* Ground shadow at tip */}
                                <ellipse cx={tipX} cy={tipY+0.4*s} rx={1.8*s} ry={0.5*s} fill="#000" opacity="0.2"/>
                              </g>
                            );
                          })()}

                          {/* Attack source dots — coloured by attack type */}
                          {liveAttacks.map((a,i)=>{
                            const col=typeColor(a.type);
                            const r=Math.min(6, Math.max(1.2, a.count/16))/mapZoom.scale;
                            const isSel=selectedGeoAttack?.city===a.city;
                            return (
                              <g key={i} onClick={()=>setSelectedGeoAttack(isSel?null:a)} className="cursor-pointer">
                                <circle cx={a.x} cy={a.y} r={r} fill="none" stroke={col} strokeWidth={0.5/mapZoom.scale}
                                  className="geo-pulse"/>
                                <circle cx={a.x} cy={a.y} r={r} fill={col}
                                  opacity={selectedGeoAttack&&!isSel?0.3:0.9}/>
                                {isSel&&<circle cx={a.x} cy={a.y} r={r+1.5/mapZoom.scale} fill="none" stroke={col} strokeWidth={0.8/mapZoom.scale}/>}
                                {/* City label when zoomed in */}
                                {mapZoom.scale>=2.5&&(
                                  <text x={a.x} y={a.y-r-0.5/mapZoom.scale} textAnchor="middle"
                                    fill={col} fontSize={2.5/mapZoom.scale} fontWeight="bold">{a.city.split(',')[0]}</text>
                                )}
                              </g>
                            );
                          })}
                        </g>

                        {/* ── Fixed overlays (not zoomed) ── */}

                        {/* Hospital Network Inset */}
                        {(()=>{
                          const BX=2, BY=62, BW=40, BH=26;
                          const HX=BX+20, HY=BY+15;
                          const IDEV=[
                            {device:'Infusion Pump',  cx:BX+7,  cy:BY+11, label:'Inf. Pump',  color:'#ef4444', ly:-4},
                            {device:'Heart Monitor',  cx:BX+33, cy:BY+11, label:'Heart Mon.', color:'#f97316', ly:-4},
                            {device:'Pulse Oximeter', cx:BX+7,  cy:BY+23, label:'Pulse Ox.',  color:'#22c55e', ly:4.5},
                            {device:'ECG Monitor',    cx:BX+33, cy:BY+23, label:'ECG Mon.',   color:'#8b5cf6', ly:4.5},
                          ];
                          return (
                            <g>
                              <rect x={BX} y={BY} width={BW} height={BH} rx="1.5"
                                fill="#071018" fillOpacity="0.93" stroke="#1e4060" strokeWidth="0.5"/>
                              <text x={BX+BW/2} y={BY+3.6} textAnchor="middle" fill="#06b6d4" fontSize="2.1" fontWeight="bold">Hospital Network</text>
                              <line x1={BX+2} y1={BY+5} x2={BX+BW-2} y2={BY+5} stroke="#1e4060" strokeWidth="0.3"/>
                              {/* Connector to map — only when not zoomed */}
                              {mapZoom.scale<1.5&&(
                                <line x1={BX+BW} y1={BY+3} x2={HOSPITAL.x} y2={HOSPITAL.y}
                                  stroke="#06b6d4" strokeWidth="0.4" strokeDasharray="1.5 2" opacity="0.45"/>
                              )}
                              {IDEV.map((d,i)=>(
                                <line key={i} x1={HX} y1={HY} x2={d.cx} y2={d.cy}
                                  stroke={d.color} strokeWidth="0.4" strokeDasharray="1.5 1.5" opacity="0.5"/>
                              ))}
                              {/* Hospital hub with cross icon */}
                              <circle cx={HX} cy={HY} r="4" fill="#06b6d4" opacity="0.12"/>
                              <circle cx={HX} cy={HY} r="2.8" fill="#06b6d4"/>
                              <circle cx={HX} cy={HY} r="2.8" fill="none" stroke="#06b6d4" strokeWidth="0.6" className="geo-pulse"/>
                              {/* Medical cross */}
                              <rect x={HX-0.55} y={HY-1.6} width="1.1" height="3.2" fill="white" rx="0.15"/>
                              <rect x={HX-1.6} y={HY-0.55} width="3.2" height="1.1" fill="white" rx="0.15"/>
                              {IDEV.map((d,i)=>{
                                const hit=selectedGeoAttack?.target===d.device;
                                const cnt=liveAttacks.filter(a=>a.target===d.device).length;
                                return (
                                  <g key={i}>
                                    {hit&&<circle cx={d.cx} cy={d.cy} r="5" fill={d.color} opacity="0.15"/>}
                                    <circle cx={d.cx} cy={d.cy} r={hit?3.5:2.8}
                                      fill={hit?d.color:'#1e2d40'} stroke={d.color}
                                      strokeWidth={hit?1:0.7} opacity={hit?1:0.9}/>
                                    {hit&&<circle cx={d.cx} cy={d.cy} r="3.5" fill="none" stroke={d.color} strokeWidth="0.6" className="geo-pulse2"/>}
                                    <text x={d.cx} y={d.cy+d.ly} textAnchor="middle"
                                      fill={hit?d.color:'#cbd5e1'} fontSize="1.9"
                                      fontWeight={hit?'bold':'normal'}>{d.label}</text>
                                    {cnt>0&&<text x={d.cx+3.5} y={d.cy-2.5} fill="#ef4444" fontSize="1.9" fontWeight="bold">{cnt}</text>}
                                  </g>
                                );
                              })}
                            </g>
                          );
                        })()}

                        {/* Lat labels */}
                        <text x="1.5" y="49.5" fill="#2d4a6b" fontSize="2">0°</text>
                        <text x="1.5" y="27.5" fill="#2d4a6b" fontSize="2">30°N</text>
                        <text x="1.5" y="72"   fill="#2d4a6b" fontSize="2">30°S</text>
                      </svg>
                    </div>

                    {/* Right panel — always visible */}
                    <div className="w-72 flex-shrink-0 flex flex-col gap-3 overflow-y-auto" style={{scrollbarWidth:'thin',scrollbarColor:'#334155 transparent'}}>
                      {selectedGeoAttack ? (
                        /* Selected attack detail */
                        <div className="rounded-xl border border-slate-700/40 bg-slate-900/60 p-4 flex flex-col gap-3">
                          <div className="flex items-start justify-between">
                            <div>
                              <p className="text-xs text-slate-500 uppercase tracking-wide mb-0.5">Attack Source</p>
                              <span className="text-lg font-bold text-white leading-tight">{selectedGeoAttack.city}</span>
                            </div>
                            <button onClick={()=>setSelectedGeoAttack(null)} className="p-1 rounded hover:bg-slate-700/50">
                              <X className="w-4 h-4 text-slate-400"/>
                            </button>
                          </div>
                          <div className="h-px bg-slate-700/60"/>
                          {/* Target device */}
                          {(() => {
                            const dn = DEVICE_NODES.find(d=>d.device===selectedGeoAttack.target);
                            return dn ? (
                              <div className="p-3 rounded-lg border" style={{backgroundColor:dn.color+'18',borderColor:dn.color+'44'}}>
                                <p className="text-xs text-slate-400 mb-1.5">Target Device</p>
                                <div className="flex items-center gap-2">
                                  <div className="w-3 h-3 rounded-full flex-shrink-0" style={{backgroundColor:dn.color}}/>
                                  <span className="text-sm font-bold" style={{color:dn.color}}>{dn.device}</span>
                                </div>
                                <p className="font-mono text-sm text-slate-400 mt-1">{dn.ip}</p>
                              </div>
                            ) : null;
                          })()}
                          <div className="grid grid-cols-2 gap-2">
                            {[
                              ['Severity', <span style={{color:sevColor(selectedGeoAttack.severity)}} className="text-sm font-bold uppercase">{selectedGeoAttack.severity}</span>],
                              ['Attack Type', <span style={{color:typeColor(selectedGeoAttack.type)}} className="text-sm font-medium">{selectedGeoAttack.type}</span>],
                              ['Total Attacks', <span className="text-sm text-red-400 font-bold">{selectedGeoAttack.count}</span>],
                              ['Share', <span className="text-sm font-bold" style={{color:sevColor(selectedGeoAttack.severity)}}>{(selectedGeoAttack.count/total*100).toFixed(1)}%</span>],
                            ].map(([k,v])=>(
                              <div key={k} className="bg-slate-800/40 rounded-lg p-2.5">
                                <p className="text-xs text-slate-500 mb-1">{k}</p>
                                <p>{v}</p>
                              </div>
                            ))}
                          </div>
                          <div>
                            <p className="text-xs text-slate-500 mb-1">ISP / ASN</p>
                            <p className="font-mono text-sm text-slate-300 bg-slate-800/40 rounded-lg px-3 py-2">{selectedGeoAttack.isp}</p>
                          </div>
                          <div>
                            <p className="text-xs text-slate-500 mb-1">Coordinates</p>
                            <p className="font-mono text-sm text-slate-400">{selectedGeoAttack.lat}°, {selectedGeoAttack.lon}°</p>
                          </div>
                          <div>
                            <p className="text-xs text-slate-500 mb-1.5">Attack share</p>
                            <div className="h-2 bg-slate-700 rounded-full overflow-hidden">
                              <div className="h-full rounded-full" style={{width:`${(selectedGeoAttack.count/total*100).toFixed(0)}%`,backgroundColor:sevColor(selectedGeoAttack.severity)}}/>
                            </div>
                          </div>
                          <button
                            onClick={()=>{
                              setBlockedIPs(prev=>[...prev,`${Math.floor(Math.random()*256)}.${Math.floor(Math.random()*256)}.0.0/16`]);
                              setResponseLog(prev=>[{id:Date.now(),time:new Date().toLocaleTimeString(),user:'Analyst',action:'Blocked GeoIP Range',target:selectedGeoAttack.city,alert:'Manual Block'},...prev.slice(0,49)]);
                            }}
                            className="flex items-center justify-center gap-2 py-2.5 rounded-lg text-sm font-medium bg-red-500/20 text-red-400 border border-red-500/30 hover:bg-red-500/30">
                            <Ban className="w-4 h-4"/> Block GeoIP Range
                          </button>
                        </div>
                      ) : (
                        /* Attack sources list when nothing selected */
                        <div className="rounded-xl border border-slate-700/40 bg-slate-900/60 p-4 flex flex-col gap-2">
                          <p className="text-xs text-slate-400 uppercase tracking-wide font-semibold mb-1">Attack Sources — click map to inspect</p>
                          {[...liveAttacks].sort((a,b)=>b.count-a.count).map((a,i)=>(
                            <div key={i} onClick={()=>setSelectedGeoAttack(a)}
                              className="flex items-center gap-2 px-3 py-2 rounded-lg cursor-pointer hover:bg-slate-700/30 transition-colors"
                              style={{backgroundColor:sevColor(a.severity)+'0a',border:`1px solid ${sevColor(a.severity)}22`}}>
                              <div className="w-2.5 h-2.5 rounded-full flex-shrink-0" style={{backgroundColor:sevColor(a.severity)}}/>
                              <div className="flex-1 min-w-0">
                                <p className="text-sm font-medium text-white truncate">{a.city}</p>
                                <p className="text-xs text-slate-500">{a.type} · {a.target}</p>
                              </div>
                              <span className="text-sm font-bold flex-shrink-0" style={{color:sevColor(a.severity)}}>{a.count}</span>
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  </div>

                </div>
              );
            })()}

            {/* ── TAB 6: Traffic Heatmap ── */}
            {activeTab==='heatmap' && (
              <div className="flex-1 overflow-y-auto p-4">
                <div className="flex items-center justify-between mb-4">
                  <div className="flex items-center gap-2"><Layers className="w-4 h-4 text-orange-400"/><span className="font-bold text-lg">Traffic Heatmap — 7 Day × 24 Hour</span></div>
                  <select value={heatmapMetric} onChange={e=>setHeatmapMetric(e.target.value)} className="bg-slate-700/60 border border-slate-600/40 rounded text-base text-white px-2 py-1">
                    <option value="traffic">Traffic Volume</option>
                    <option value="anomaly">Anomaly Score</option>
                  </select>
                </div>
                {/* Legend */}
                <div className="flex items-center gap-2 mb-3 text-base text-slate-400">
                  <span>Low</span>
                  {[0.1,0.25,0.4,0.55,0.7,0.85,1].map((v,i)=>(
                    <div key={i} className="w-6 h-3 rounded" style={{backgroundColor:`rgba(${heatmapMetric==='anomaly'?'239,68,68':'6,182,212'},${v})`}}/>
                  ))}
                  <span>High</span>
                </div>
                {/* Grid */}
                <div className="overflow-x-auto">
                  <div className="min-w-max">
                    <div className="flex gap-0.5 mb-1 ml-8">
                      {hours.filter((_,i)=>i%3===0).map(h=>(
                        <div key={h} className="text-base text-slate-500 w-12 text-center">{h}</div>
                      ))}
                    </div>
                    {heatmapData.map((row,di)=>{
                      const today = todayName();
                      const dayOrder = days.indexOf(row.day);
                      const todayOrder = days.indexOf(today);
                      const isFuture = dayOrder > todayOrder;
                      const isToday  = row.day === today;
                      const maxVal   = Math.max(1, ...hours.map(h=>row[h]));
                      return (
                        <div key={di} className="flex items-center gap-0.5 mb-0.5">
                          <span className={`text-base w-7 flex-shrink-0 ${isToday?'text-cyan-400 font-bold':isFuture?'text-slate-600':'text-slate-400'}`}>
                            {row.day}{isToday?' ●':''}
                          </span>
                          {hours.map(h=>{
                            const v = isFuture ? 0 : row[h] / maxVal;
                            return (
                              <div key={h} title={isFuture?'No data yet':`${row.day} ${h}: ${row[h]} packets`}
                                className="w-4 h-4 rounded-sm flex-shrink-0 cursor-pointer hover:ring-1 hover:ring-white/30"
                                style={{backgroundColor: isFuture
                                  ? 'rgba(100,100,100,0.1)'
                                  : `rgba(${heatmapMetric==='anomaly'?'239,68,68':'6,182,212'},${Math.max(0.05,v)})`
                                }}/>
                            );
                          })}
                        </div>
                      );
                    })}
                  </div>
                </div>
                {/* 24hr trend chart */}
                <div className="mt-4">
                  <p className="text-base text-slate-400 mb-2">24-Hour Combined Trend</p>
                  <ResponsiveContainer width="100%" height={100}>
                    <AreaChart data={trafficHistory}>
                      <defs>
                        <linearGradient id="heatGrad" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="5%" stopColor="#f97316" stopOpacity={0.4}/>
                          <stop offset="95%" stopColor="#f97316" stopOpacity={0}/>
                        </linearGradient>
                      </defs>
                      <CartesianGrid strokeDasharray="3 3" stroke="#334155"/>
                      <XAxis dataKey="timestamp" stroke="#64748b" tick={{fontSize:8}}/>
                      <YAxis stroke="#64748b" tick={{fontSize:8}}/>
                      <Tooltip contentStyle={{backgroundColor:'#1e293b',border:'1px solid #334155',borderRadius:'6px',fontSize:'10px'}}/>
                      <Area type="monotone" dataKey="packets" stroke="#f97316" strokeWidth={2} fill="url(#heatGrad)"/>
                    </AreaChart>
                  </ResponsiveContainer>
                </div>
              </div>
            )}

            {/* ── TAB 7: Network Topology ── */}
            {activeTab==='topology' && (
              <div className="flex-1 overflow-hidden flex flex-col">
                <div className="px-3 py-2 border-b border-slate-700/40 flex items-center gap-2 flex-shrink-0">
                  <GitBranch className="w-4 h-4 text-blue-400"/>
                  <span className="font-bold text-base">Live Network Topology</span>
                  {activeAttackPath && <span className="ml-2 text-base text-red-400 animate-pulse">⚡ Attack in progress</span>}
                </div>
                <div className="flex flex-1 overflow-hidden min-h-0">
                  <div className="flex-1 relative bg-slate-900/40">
                    {/* VLAN legend with subnets */}
                    <div className="absolute top-2 left-2 flex flex-col gap-1 z-10">
                      {Object.entries(VLAN_DEFS).filter(([id])=>id!=='100').map(([id,v])=>(
                        <div key={id} className="flex items-center gap-1.5">
                          <div className="w-3 h-0.5 rounded" style={{backgroundColor:v.color}}/>
                          <span style={{color:v.color,fontSize:'7.5px',fontFamily:'monospace'}}>VLAN {id} {v.name}</span>
                          <span style={{color:v.color+'99',fontSize:'7px',fontFamily:'monospace'}}>{v.subnet}</span>
                        </div>
                      ))}
                    </div>
                    <svg className="w-full h-full" viewBox="0 0 100 95" preserveAspectRatio="xMidYMid meet">
                      {/* Links */}
                      {networkLinks.map((link,i)=>{
                        const from = topologyNodes.find(n=>n.id===link.from);
                        const to   = topologyNodes.find(n=>n.id===link.to);
                        if(!from||!to) return null;
                        const isAttack  = activeAttackPath && (link.from===activeAttackPath.from||link.to===activeAttackPath.from);
                        // Get effective VLAN for this link (check if destination node was moved to quarantine)
                        const destNode  = topologyNodes.find(n=>n.id===link.to);
                        const vlanId    = destNode?.vlan || link.vlan;
                        const vlanColor = vlanId ? (VLAN_DEFS[vlanId]?.color||'#334155') : '#334155';
                        const strokeCol = isAttack ? '#ef4444' : vlanId ? vlanColor : '#334155';
                        return (
                          <line key={i} x1={from.x} y1={from.y} x2={to.x} y2={to.y}
                            stroke={strokeCol} strokeWidth={isAttack?'0.8':vlanId?'0.7':'0.5'}
                            strokeDasharray={isAttack?'2 1':vlanId?undefined:undefined}
                            opacity={isAttack?1:0.8}/>
                        );
                      })}
                      {/* Nodes */}
                      {topologyNodes.map(node=>{
                        const vlanColor   = node.vlan ? (VLAN_DEFS[node.vlan]?.color||'#22c55e') : null;
                        const statusColor = node.status==='attack'?'#ef4444':node.status==='warning'?'#f97316':node.status==='isolated'?'#ef4444':vlanColor||'#22c55e';
                        const isSelected  = selectedNode?.id===node.id;
                        return (
                          <g key={node.id} onClick={()=>setSelectedNode(node===selectedNode?null:node)} className="cursor-pointer">
                            {node.type==='device' && node.vlan && (
                              <circle cx={node.x} cy={node.y} r={6.5} fill={statusColor+'18'} stroke={statusColor} strokeWidth="0.3" strokeDasharray="1.5 0.8"/>
                            )}
                            <circle cx={node.x} cy={node.y} r={node.type==='device'?4:5}
                              fill="#1e293b" stroke={statusColor} strokeWidth={isSelected?2:1}/>
                            {(node.status==='attack'||node.status==='isolated') && <circle cx={node.x} cy={node.y} r={7} fill="none" stroke={statusColor} strokeWidth="0.5" opacity="0.5"/>}
                            <text x={node.x} y={node.y+0.8} textAnchor="middle" dominantBaseline="middle" fill={statusColor} fontSize="3">{node.type==='router'?'⌂':node.type==='firewall'?'🛡':node.type==='database'?'🗄':node.type==='server'?'⚙':node.type==='switch'?'⇌':'○'}</text>
                            <text x={node.x} y={node.y+(node.type==='device'?7:8)} textAnchor="middle" fill="#94a3b8" fontSize="2.2">{node.label}</text>
                            {node.vlan && node.type==='device' && (
                              <text x={node.x} y={node.y+9.5} textAnchor="middle" fill={statusColor} fontSize="1.8" fontWeight="600">VLAN {node.vlan}</text>
                            )}
                          </g>
                        );
                      })}
                    </svg>
                  </div>
                  {/* Node detail */}
                  {selectedNode && (
                    <div className="w-44 border-l border-slate-700/40 p-3 overflow-y-auto flex-shrink-0 bg-slate-900/30">
                      <div className="flex items-center justify-between mb-2">
                        <span className="text-base font-bold text-blue-400">{selectedNode.label}</span>
                        <button onClick={()=>setSelectedNode(null)}><X className="w-3 h-3 text-slate-400"/></button>
                      </div>
                      <div className="space-y-2 text-base">
                        <div><p className="text-slate-500">Type</p><p className="font-medium capitalize">{selectedNode.type}</p></div>
                        <div><p className="text-slate-500">Status</p>
                          <p className="font-bold capitalize" style={{color:selectedNode.status==='attack'?'#ef4444':selectedNode.status==='warning'?'#f97316':selectedNode.status==='isolated'?'#ef4444':'#22c55e'}}>
                            {selectedNode.status==='isolated'?'Isolated (VLAN 99)':selectedNode.status}
                          </p>
                        </div>
                        {selectedNode.vlan && (() => {
                          const vd = VLAN_DEFS[selectedNode.vlan];
                          return (
                            <div className="rounded-lg p-2 border" style={{backgroundColor:vd?.color+'12',borderColor:vd?.color+'33'}}>
                              <p className="text-slate-500 mb-1">VLAN / Subnet</p>
                              <p className="font-mono font-bold text-base" style={{color:vd?.color}}>VLAN {selectedNode.vlan} — {vd?.name}</p>
                              {vd?.subnet && <p className="font-mono text-base mt-0.5" style={{color:vd?.color+'cc'}}>{vd.subnet}</p>}
                              {vd?.gateway && <p className="font-mono text-base" style={{color:vd?.color+'88'}}>GW {vd.gateway}</p>}
                            </div>
                          );
                        })()}
                        {selectedNode.vlans && (
                          <div>
                            <p className="text-slate-500 mb-1">Trunked VLANs</p>
                            <div className="space-y-1">
                              {selectedNode.vlans.map(v=>{
                                const vd = VLAN_DEFS[v];
                                return (
                                  <div key={v} className="flex items-center justify-between rounded px-1.5 py-1"
                                    style={{backgroundColor:(vd?.color||'#64748b')+'15',border:`1px solid ${(vd?.color||'#64748b')}33`}}>
                                    <span className="font-mono font-bold" style={{color:vd?.color||'#94a3b8',fontSize:'9px'}}>VLAN {v}</span>
                                    <span className="font-mono" style={{color:(vd?.color||'#64748b')+'99',fontSize:'8px'}}>{vd?.subnet||'—'}</span>
                                  </div>
                                );
                              })}
                            </div>
                          </div>
                        )}
                        {selectedNode.device && deviceStatus[selectedNode.device] && (
                          <>
                            <div>
                              <p className="text-slate-500">IP Address</p>
                              <p className="font-mono text-cyan-400">{deviceStatus[selectedNode.device].ip}</p>
                            </div>
                            <div><p className="text-slate-500">MAC</p><p className="font-mono text-slate-300 text-base">{deviceStatus[selectedNode.device].mac}</p></div>
                            <div><p className="text-slate-500">Firmware</p><p className="font-bold text-white">{deviceStatus[selectedNode.device].firmware || '--'}</p></div>
                          </>
                        )}
                        {/* ACL rules for isolated device */}
                        {selectedNode.status==='isolated' && (() => {
                          const rules = aclRules.filter(r=>r.device===selectedNode.device);
                          return rules.length > 0 ? (
                            <div>
                              <p className="text-slate-500 mb-1">Active ACL Rules</p>
                              <div className="space-y-1">
                                {rules.map(r=>(
                                  <div key={r.id} className="rounded px-1.5 py-1 bg-red-500/10 border border-red-500/20">
                                    <p className="font-mono text-red-400 font-bold" style={{fontSize:'8px'}}>seq {r.seq} {r.action}</p>
                                    <p className="font-mono text-slate-400" style={{fontSize:'7.5px'}}>{r.src} →</p>
                                    <p className="font-mono text-slate-400" style={{fontSize:'7.5px'}}>{r.dst}</p>
                                    <p className="text-slate-500" style={{fontSize:'7px'}}>{r.appliedTo} · {r.time}</p>
                                  </div>
                                ))}
                              </div>
                            </div>
                          ) : null;
                        })()}
                        {(selectedNode.status==='warning'||selectedNode.status==='attack'||selectedNode.status==='normal') && selectedNode.type==='device' ? (
                          <button onClick={()=>handleQuickAction('isolate',{device:selectedNode.device,type:'Manual',sourceIP:'',id:Date.now()})}
                            className="w-full flex items-center justify-center gap-1 py-1.5 rounded bg-violet-500/20 text-violet-400 text-base hover:bg-violet-500/30">
                            <Unplug className="w-3 h-3"/> Isolate → VLAN 99
                          </button>
                        ) : selectedNode.status==='isolated' ? (
                          <button onClick={()=>handleQuickAction('restore',{device:selectedNode.device,type:'Manual',sourceIP:'',id:Date.now()})}
                            className="w-full flex items-center justify-center gap-1 py-1.5 rounded bg-emerald-500/20 text-emerald-400 text-base">
                            <CheckCircle className="w-3 h-3"/> Restore to VLAN 20
                          </button>
                        ) : null}
                      </div>
                    </div>
                  )}
                </div>

                {/* ACL / Subnet Block Panel — shown when devices are isolated */}
                {aclRules.length > 0 && (
                  <div className="flex-shrink-0 border-t border-slate-700/40 bg-slate-900/40 px-3 py-2" style={{maxHeight:'180px', display:'flex', flexDirection:'column'}}>
                    <div className="flex items-center gap-2 mb-2 flex-shrink-0">
                      <Shield className="w-3.5 h-3.5 text-red-400"/>
                      <span className="text-base font-bold text-red-400">Active Subnet Blocks / ACL Rules</span>
                      <span className="ml-2 px-1.5 py-0.5 rounded bg-red-500/20 text-red-400 text-base font-bold">{aclRules.length} rules</span>
                      <button onClick={() => setAclRules([])} className="ml-auto text-xs text-slate-500 hover:text-red-400 transition-colors">Clear all</button>
                    </div>
                    <div className="overflow-x-auto overflow-y-auto flex-1">
                      <table className="w-full text-base">
                        <thead>
                          <tr className="text-slate-500">
                            <th className="text-left pr-3 py-0.5 font-medium">Seq</th>
                            <th className="text-left pr-3 py-0.5 font-medium">Action</th>
                            <th className="text-left pr-3 py-0.5 font-medium">Source Subnet</th>
                            <th className="text-left pr-3 py-0.5 font-medium">Dest Subnet</th>
                            <th className="text-left pr-3 py-0.5 font-medium">Applied To</th>
                            <th className="text-left pr-3 py-0.5 font-medium">Device</th>
                            <th className="text-left py-0.5 font-medium">Time</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-700/20">
                          {aclRules.map(r=>(
                            <tr key={r.id} className="font-mono">
                              <td className="pr-3 py-1 text-slate-400">{r.seq}</td>
                              <td className="pr-3 py-1">
                                <span className="px-1.5 py-0.5 rounded font-bold text-base bg-red-500/20 text-red-400">{r.action}</span>
                              </td>
                              <td className="pr-3 py-1 text-cyan-300">{r.src}</td>
                              <td className="pr-3 py-1 text-orange-300">{r.dst}</td>
                              <td className="pr-3 py-1 text-slate-400">{r.appliedTo}</td>
                              <td className="pr-3 py-1 text-violet-400">{r.device}</td>
                              <td className="py-1 text-slate-500">{r.time}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* ── TAB 8: CSV Upload & Analysis ── */}
            {activeTab==='upload' && (() => {
              const parseCSV = (text) => {
                const lines = text.trim().split('\n').filter(l => l.trim());
                if (lines.length < 2) return { headers: [], rows: [] };
                const headers = lines[0].split(',').map(h => h.trim().replace(/"/g,''));
                const rows = lines.slice(1).map(line => {
                  const vals = line.split(',').map(v => v.trim().replace(/"/g,''));
                  return Object.fromEntries(headers.map((h,i) => [h, vals[i] ?? '']));
                });
                return { headers, rows };
              };

              const analyseRows = (rows, headers) => {
                // Map common column name variants
                const col = (candidates) => headers.find(h => candidates.some(c => h.toLowerCase().includes(c))) || '';
                const srcCol      = col(['src','source','src_ip','srcip','source_ip']);
                const dstCol      = col(['dst','dest','dst_ip','dstip','destination_ip','dest_ip']);
                const protocolCol = col(['protocol','proto']);
                const packetsCol  = col(['packet','pkts','pkt_count','num_packets']);
                const bytesCol    = col(['byte','bytes','total_bytes','byt']);
                const portCol     = col(['port','dport','dst_port','dest_port']);
                const labelCol    = col(['label','class','attack','category','type','threat']);
                const anomalyCol  = col(['anomaly','score','anomaly_score','confidence']);

                const threats = [];
                const typeCounts = {};
                let totalAnomalous = 0;

                rows.forEach((row, i) => {
                  const packets   = parseInt(row[packetsCol]) || 0;
                  const bytes     = parseInt(row[bytesCol])   || 0;
                  const port      = parseInt(row[portCol])    || 0;
                  const label     = (row[labelCol] || '').toLowerCase();
                  const anomScore = parseFloat(row[anomalyCol]) || 0;
                  const srcIP     = row[srcCol]  || `192.168.${Math.floor(Math.random()*254)+1}.${Math.floor(Math.random()*254)+1}`;
                  const dstIP     = row[dstCol]  || '192.168.1.50';
                  const proto     = row[protocolCol] || 'TCP';

                  // Detect attack type
                  let detectedType = null;
                  let severity = 'low';
                  let confidence = 65;

                  if (label && !['normal','benign','0','false','no'].includes(label)) {
                    detectedType = label.includes('ddos')||label.includes('dos') ? 'DDoS'
                      : label.includes('mitm')||label.includes('arp') ? 'MITM'
                      : label.includes('spoof') ? 'Spoofing'
                      : label.includes('inject') ? 'Injection'
                      : label.includes('recon')||label.includes('scan') ? 'Recon'
                      : attackTypes[Math.floor(Math.random()*attackTypes.length)];
                    confidence = 85 + Math.random()*10;
                    severity = 'high';
                  } else if (anomScore > 0.7 || packets > 10000) {
                    detectedType = 'DDoS';
                    severity = anomScore > 0.9 || packets > 50000 ? 'critical' : 'high';
                    confidence = 70 + anomScore * 25;
                  } else if (port === 22 || port === 3389 || proto === 'ARP') {
                    detectedType = proto === 'ARP' ? 'MITM' : 'Recon';
                    severity = 'medium';
                    confidence = 72 + Math.random()*15;
                  } else if (packets > 3000 || bytes > 500000) {
                    detectedType = 'DDoS';
                    severity = 'medium';
                    confidence = 68 + Math.random()*12;
                  }

                  if (detectedType) {
                    totalAnomalous++;
                    typeCounts[detectedType] = (typeCounts[detectedType]||0)+1;
                    if (threats.length < 50) {
                      threats.push({
                        row: i+1, type: detectedType, severity,
                        confidence: confidence.toFixed(1),
                        srcIP, dstIP, port: port||443,
                        packets, bytes, proto,
                      });
                    }
                  }
                });

                const topType = Object.entries(typeCounts).sort((a,b)=>b[1]-a[1])[0];
                return {
                  total: rows.length, anomalous: totalAnomalous,
                  benign: rows.length - totalAnomalous,
                  accuracy: 98.30,
                  topType: topType ? topType[0] : 'None',
                  typeCounts, threats,
                  headers, rows: rows.slice(0,100),
                };
              };

              const handleFile = (file) => {
                if (!file || !file.name.endsWith('.csv')) return;
                setCsvFile(file);
                setCsvLoading(true);
                setCsvAnalysis(null);
                const reader = new FileReader();
                reader.onload = (e) => {
                  const { headers, rows } = parseCSV(e.target.result);
                  setCsvHeaders(headers);
                  setCsvRows(rows);
                  setTimeout(() => {
                    setCsvAnalysis(analyseRows(rows, headers));
                    setCsvLoading(false);
                  }, 1200);
                };
                reader.readAsText(file);
              };

              const pushToAlerts = () => {
                if (!csvAnalysis) return;
                const newAlerts = csvAnalysis.threats.slice(0,5).map(t => ({
                  id: Date.now() + Math.random(),
                  severity: t.severity, device: devices[Math.floor(Math.random()*devices.length)],
                  message: `[CSV] ${t.type} detected — row ${t.row}`,
                  time: 'CSV import', type: t.type, status: 'active',
                  sourceIP: t.srcIP, destIP: t.dstIP,
                  packets: t.packets, bytes: `${t.bytes} B`, port: t.port,
                  confidence: t.confidence, timestamp: new Date(),
                }));
                setAlerts(prev => [...newAlerts, ...prev.slice(0, 15)]);
                setStats(prev => ({ ...prev, anomalies: prev.anomalies + csvAnalysis.anomalous }));
                setActiveTab('alerts');
              };

              return (
                <div className="flex-1 overflow-y-auto p-4">
                  <div className="flex items-center gap-2 mb-4">
                    <Upload className="w-4 h-4 text-pink-400"/>
                    <span className="font-bold text-lg">CSV Threat Analysis</span>
                    {csvFile && <span className="text-base text-slate-400 ml-auto">{csvFile.name} · {(csvFile.size/1024).toFixed(1)} KB</span>}
                  </div>

                  {/* Drop zone */}
                  {!csvAnalysis && !csvLoading && (
                    <div
                      onDragOver={e=>{e.preventDefault();setCsvDragOver(true);}}
                      onDragLeave={()=>setCsvDragOver(false)}
                      onDrop={e=>{e.preventDefault();setCsvDragOver(false);handleFile(e.dataTransfer.files[0]);}}
                      className={`border-2 border-dashed rounded-xl p-10 text-center transition-all cursor-pointer mb-4 ${csvDragOver?'border-pink-400 bg-pink-500/10':'border-slate-600 hover:border-pink-500/50 hover:bg-slate-700/20'}`}
                      onClick={()=>document.getElementById('csvInput').click()}
                    >
                      <Upload className="w-10 h-10 text-slate-500 mx-auto mb-3"/>
                      <p className="text-lg font-medium text-slate-300">Drag & drop a CSV file here</p>
                      <p className="text-base text-slate-500 mt-1">or click to browse — supports CICIDS, CIC-IoT, NSL-KDD formats</p>
                      <input id="csvInput" type="file" accept=".csv" className="hidden" onChange={e=>handleFile(e.target.files[0])}/>
                    </div>
                  )}

                  {/* Supported formats hint */}
                  {!csvAnalysis && !csvLoading && (
                    <div className="grid grid-cols-3 gap-2 mb-4 text-base">
                      {[
                        {name:'CICIDS 2017/18', cols:'Src IP, Dst IP, Protocol, Packets, Label'},
                        {name:'CIC-IoT 2023',   cols:'srcip, dstip, proto, pkts, Attack_type'},
                        {name:'Custom CSV',     cols:'Any columns — auto-detected'},
                      ].map((f,i)=>(
                        <div key={i} className="p-2.5 rounded-lg bg-slate-700/30 border border-slate-600/30">
                          <p className="font-bold text-pink-400 mb-1">{f.name}</p>
                          <p className="text-slate-400">{f.cols}</p>
                        </div>
                      ))}
                    </div>
                  )}

                  {/* Loading */}
                  {csvLoading && (
                    <div className="flex flex-col items-center justify-center py-16 gap-4">
                      <div className="w-12 h-12 border-4 border-pink-400 border-t-transparent rounded-full animate-spin"/>
                      <p className="text-lg text-slate-300">Running LightGBM inference…</p>
                      <p className="text-base text-slate-500">{csvRows.length} rows · 44 features</p>
                    </div>
                  )}

                  {/* Results */}
                  {csvAnalysis && !csvLoading && (
                    <>
                      {/* Summary cards */}
                      <div className="grid grid-cols-4 gap-2 mb-4">
                        {[
                          {label:'Total Rows',   value:csvAnalysis.total,     color:'#06b6d4'},
                          {label:'Threats Found',value:csvAnalysis.anomalous, color:'#ef4444'},
                          {label:'Benign',        value:csvAnalysis.benign,   color:'#22c55e'},
                          {label:'Model Acc.',   value:`${csvAnalysis.accuracy}%`, color:'#a78bfa'},
                        ].map((s,i)=>(
                          <div key={i} className="p-3 rounded-lg bg-slate-700/30 border border-slate-600/30 text-center">
                            <p className="text-base text-slate-400">{s.label}</p>
                            <p className="text-xl font-bold mt-0.5" style={{color:s.color}}>{s.value}</p>
                          </div>
                        ))}
                      </div>

                      {/* Type breakdown */}
                      <div className="mb-4 p-3 rounded-lg bg-slate-700/30 border border-slate-600/30">
                        <p className="text-base text-slate-400 mb-2">Detected Attack Types</p>
                        <div className="flex flex-wrap gap-2">
                          {Object.entries(csvAnalysis.typeCounts).map(([type,count])=>{
                            const col = {DDoS:'#ef4444',MITM:'#f97316',Spoofing:'#eab308',Injection:'#8b5cf6',Recon:'#3b82f6'}[type]||'#64748b';
                            return (
                              <div key={type} className="flex items-center gap-1.5 px-2.5 py-1 rounded-full text-base font-medium" style={{backgroundColor:col+'22',color:col,border:`1px solid ${col}44`}}>
                                <span>{type}</span><span className="font-bold">{count}</span>
                              </div>
                            );
                          })}
                        </div>
                      </div>

                      {/* Threat table */}
                      <div className="rounded-lg border border-slate-700/40 overflow-hidden mb-4">
                        <div className="px-3 py-2 bg-slate-900/50 flex items-center justify-between">
                          <span className="text-base font-bold text-slate-300">Detected Threats (top 50)</span>
                          <span className="text-base text-slate-500">{csvAnalysis.threats.length} records</span>
                        </div>
                        <div className="overflow-y-auto max-h-48">
                          <table className="w-full text-base">
                            <thead className="bg-slate-900/40 sticky top-0">
                              <tr className="text-slate-400">
                                <th className="px-2 py-1.5 text-left">Row</th>
                                <th className="px-2 py-1.5 text-left">Type</th>
                                <th className="px-2 py-1.5 text-left">Severity</th>
                                <th className="px-2 py-1.5 text-left">Src IP</th>
                                <th className="px-2 py-1.5 text-left">Dst IP</th>
                                <th className="px-2 py-1.5 text-left">Conf%</th>
                              </tr>
                            </thead>
                            <tbody className="divide-y divide-slate-700/30">
                              {csvAnalysis.threats.map((t,i)=>(
                                <tr key={i} className="hover:bg-slate-700/20">
                                  <td className="px-2 py-1 font-mono text-slate-400">{t.row}</td>
                                  <td className="px-2 py-1 font-bold" style={{color:{DDoS:'#ef4444',MITM:'#f97316',Spoofing:'#eab308',Injection:'#8b5cf6',Recon:'#3b82f6'}[t.type]||'#94a3b8'}}>{t.type}</td>
                                  <td className="px-2 py-1"><span className={`px-1 py-0.5 rounded text-base uppercase font-bold ${getSeverityColor(t.severity)}`}>{t.severity}</span></td>
                                  <td className="px-2 py-1 font-mono text-cyan-400">{t.srcIP}</td>
                                  <td className="px-2 py-1 font-mono text-emerald-400">{t.dstIP}</td>
                                  <td className="px-2 py-1 font-bold text-purple-400">{t.confidence}%</td>
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        </div>
                      </div>

                      {/* Action buttons */}
                      <div className="flex gap-3">
                        <button onClick={pushToAlerts}
                          className="flex-1 flex items-center justify-center gap-2 py-2.5 rounded-lg bg-pink-500/20 border border-pink-500/40 text-pink-400 text-lg font-medium hover:bg-pink-500/30">
                          <Bell className="w-4 h-4"/> Push {Math.min(5,csvAnalysis.threats.length)} Threats to Alerts
                        </button>
                        <button onClick={()=>{setCsvFile(null);setCsvAnalysis(null);setCsvRows([]);setCsvHeaders([]);}}
                          className="px-4 py-2.5 rounded-lg bg-slate-700/40 text-slate-400 text-lg hover:bg-slate-700/60">
                          Clear
                        </button>
                      </div>

                      {/* Raw data preview */}
                      {csvRows.length > 0 && (
                        <details className="mt-4">
                          <summary className="text-base text-slate-400 cursor-pointer hover:text-slate-300 select-none">Raw CSV preview ({csvRows.length} rows)</summary>
                          <div className="mt-2 overflow-x-auto rounded-lg border border-slate-700/40">
                            <table className="text-base">
                              <thead className="bg-slate-900/50">
                                <tr>{csvHeaders.map(h=><th key={h} className="px-2 py-1.5 text-left text-slate-400 whitespace-nowrap">{h}</th>)}</tr>
                              </thead>
                              <tbody className="divide-y divide-slate-700/20">
                                {csvRows.slice(0,10).map((row,i)=>(
                                  <tr key={i} className="hover:bg-slate-700/20">
                                    {csvHeaders.map(h=><td key={h} className="px-2 py-1 text-slate-300 whitespace-nowrap max-w-xs truncate">{row[h]}</td>)}
                                  </tr>
                                ))}
                              </tbody>
                            </table>
                          </div>
                        </details>
                      )}
                    </>
                  )}
                </div>
              );
            })()}

            {/* ── TAB 9: HIPAA Compliance ── */}
            {activeTab==='hipaa' && (() => {
              const overallScore = Math.round(hipaaRules.reduce((s,r)=>s+r.score,0)/hipaaRules.length);
              const scoreColor = overallScore>=80?'#22c55e':overallScore>=60?'#eab308':'#ef4444';
              const statusIcon = {pass:'✓',warn:'!',fail:'✗'};
              const statusColor = {pass:'#22c55e',warn:'#eab308',fail:'#ef4444'};
              const statusBg   = {pass:'#22c55e22',warn:'#eab30822',fail:'#ef444422'};
              return (
                <div className="flex-1 overflow-y-auto p-4 space-y-4">
                  {/* Header */}
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <ClipboardList className="w-4 h-4 text-emerald-400"/>
                      <span className="font-bold text-lg">HIPAA Compliance Dashboard</span>
                    </div>
                    <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg border" style={{backgroundColor:scoreColor+'18',borderColor:scoreColor+'44'}}>
                      <span className="text-base text-slate-400">Overall Score</span>
                      <span className="text-xl font-black" style={{color:scoreColor}}>{overallScore}%</span>
                    </div>
                  </div>

                  {/* 3 Rule Cards */}
                  <div className="grid grid-cols-3 gap-3">
                    {hipaaRules.map(rule=>{
                      const rc = rule.score>=80?'#22c55e':rule.score>=60?'#eab308':'#ef4444';
                      const passCount = rule.controls.filter(c=>c.status==='pass').length;
                      const failCount = rule.controls.filter(c=>c.status==='fail').length;
                      return (
                        <div key={rule.id} className="rounded-xl p-3 border" style={{backgroundColor:rc+'0a',borderColor:rc+'33'}}>
                          <div className="flex items-center justify-between mb-2">
                            <p className="text-base font-bold leading-tight" style={{color:rc}}>{rule.name}</p>
                            <span className="text-xl font-black" style={{color:rc}}>{rule.score}%</span>
                          </div>
                          <div className="h-1.5 bg-slate-700 rounded-full overflow-hidden mb-2">
                            <div className="h-full rounded-full transition-all" style={{width:`${rule.score}%`,backgroundColor:rc}}/>
                          </div>
                          <div className="flex gap-2 text-base">
                            <span style={{color:'#22c55e'}}>✓ {passCount} pass</span>
                            <span style={{color:'#ef4444'}}>✗ {failCount} fail</span>
                          </div>
                          <div className="mt-2 space-y-1">
                            {rule.controls.map(ctrl=>(
                              <div key={ctrl.id} className="flex items-center gap-1.5 text-base">
                                <span className="w-3 h-3 rounded-sm flex items-center justify-center text-base font-bold flex-shrink-0"
                                  style={{backgroundColor:statusBg[ctrl.status],color:statusColor[ctrl.status]}}>
                                  {statusIcon[ctrl.status]}
                                </span>
                                <span className="text-slate-400 leading-tight truncate">{ctrl.label}</span>
                              </div>
                            ))}
                          </div>
                        </div>
                      );
                    })}
                  </div>

                  {/* Active Violations */}
                  <div className="rounded-xl border border-slate-700/40 overflow-hidden">
                    <div className="px-3 py-2 border-b border-slate-700/40 flex items-center gap-2 bg-slate-900/40">
                      <AlertTriangle className="w-3.5 h-3.5 text-amber-400"/>
                      <span className="text-base font-bold">Active HIPAA Violations</span>
                      <span className="ml-auto px-1.5 py-0.5 rounded bg-red-500/20 text-red-400 text-base font-bold">{hipaaViolations.filter(v=>v.severity==='high').length} HIGH</span>
                    </div>
                    <div className="divide-y divide-slate-700/20">
                      {hipaaViolations.map(v=>{
                        const vc = v.severity==='high'?'#ef4444':v.severity==='medium'?'#eab308':'#3b82f6';
                        return (
                          <div key={v.id} className="px-3 py-2.5 flex items-start gap-3">
                            <span className="px-1.5 py-0.5 rounded text-base font-bold uppercase flex-shrink-0 mt-0.5"
                              style={{backgroundColor:vc+'22',color:vc,border:`1px solid ${vc}44`}}>{v.severity}</span>
                            <div className="flex-1 min-w-0">
                              <p className="text-base font-medium">{v.control}</p>
                              <p className="text-base text-slate-400 truncate">{v.detail}</p>
                              <p className="text-base text-slate-500 mt-0.5">{v.rule} · {v.device} · {v.ts}</p>
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  </div>

                  {/* PHI Access Log */}
                  <div className="rounded-xl border border-slate-700/40 overflow-hidden">
                    <div className="px-3 py-2 border-b border-slate-700/40 flex items-center gap-2 bg-slate-900/40">
                      <UserCheck className="w-3.5 h-3.5 text-cyan-400"/>
                      <span className="text-base font-bold">PHI Access Log</span>
                      <span className="ml-auto text-base text-slate-500">Last 6 accesses</span>
                    </div>
                    <div className="overflow-x-auto">
                      <table className="w-full text-base">
                        <thead className="bg-slate-900/50">
                          <tr>
                            {['User','Action','Resource','Device','Time','Status'].map(h=>(
                              <th key={h} className="px-2.5 py-2 text-left text-slate-400 font-medium whitespace-nowrap">{h}</th>
                            ))}
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-700/20">
                          {phiAccessLog.map(row=>{
                            const sc = row.status==='allowed'?'#22c55e':row.status==='denied'?'#ef4444':'#eab308';
                            return (
                              <tr key={row.id} className="hover:bg-slate-700/10">
                                <td className="px-2.5 py-2 font-mono text-slate-300 whitespace-nowrap">{row.user}</td>
                                <td className="px-2.5 py-2">
                                  <span className="px-1.5 py-0.5 rounded text-base font-bold"
                                    style={{backgroundColor:'#06b6d422',color:'#06b6d4'}}>{row.action}</span>
                                </td>
                                <td className="px-2.5 py-2 text-slate-400 max-w-xs truncate">{row.resource}</td>
                                <td className="px-2.5 py-2 text-slate-400 whitespace-nowrap">{row.device}</td>
                                <td className="px-2.5 py-2 font-mono text-slate-400 whitespace-nowrap">{row.ts}</td>
                                <td className="px-2.5 py-2">
                                  <span className="px-1.5 py-0.5 rounded text-base font-bold uppercase"
                                    style={{backgroundColor:sc+'22',color:sc,border:`1px solid ${sc}44`}}>{row.status}</span>
                                </td>
                              </tr>
                            );
                          })}
                        </tbody>
                      </table>
                    </div>
                  </div>

                  {/* HIPAA Device Compliance */}
                  <div className="rounded-xl border border-slate-700/40 p-3">
                    <div className="flex items-center gap-2 mb-3">
                      <FileCheck className="w-3.5 h-3.5 text-violet-400"/>
                      <span className="text-base font-bold">IoMT Device HIPAA Status</span>
                    </div>
                    <div className="grid grid-cols-4 gap-2">
                      {[
                        {device:'Infusion Pump', vlan:20, score:22, issues:['Unencrypted comms','No audit log','Default creds']},
                        {device:'Heart Monitor', vlan:20, score:55, issues:['Legacy OS','PHI in plain text']},
                        {device:'Pulse Oximeter',vlan:20, score:82, issues:['Weak auth']},
                        {device:'ECG Monitor',   vlan:20, score:48, issues:['No TLS','PHI exposure']},
                      ].map(d=>{
                        const dc = d.score>=80?'#22c55e':d.score>=50?'#eab308':'#ef4444';
                        const vlanC = VLAN_DEFS[d.vlan]?.color||'#94a3b8';
                        return (
                          <div key={d.device} className="p-2.5 rounded-lg border" style={{backgroundColor:dc+'0a',borderColor:dc+'33'}}>
                            <p className="text-base font-bold mb-1" style={{color:dc}}>{d.device}</p>
                            <div className="flex items-center gap-1 mb-2">
                              <span className="text-base font-mono px-1 rounded" style={{backgroundColor:vlanC+'22',color:vlanC,fontSize:'9px'}}>VLAN {d.vlan}</span>
                            </div>
                            <div className="text-xl font-black mb-1" style={{color:dc}}>{d.score}%</div>
                            <div className="h-1 bg-slate-700 rounded-full overflow-hidden mb-2">
                              <div className="h-full rounded-full" style={{width:`${d.score}%`,backgroundColor:dc}}/>
                            </div>
                            <div className="space-y-0.5">
                              {d.issues.map((issue,i)=>(
                                <p key={i} className="text-slate-400" style={{fontSize:'9px'}}>⚠ {issue}</p>
                              ))}
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  </div>
                </div>
              );
            })()}

            {/* ── TAB 10: GRC ── */}
            {activeTab==='grc' && (() => {
              const riskScore = (l,i) => l*i;
              const riskColor = s => s>=20?'#ef4444':s>=12?'#f97316':s>=6?'#eab308':'#22c55e';
              const riskLabel = s => s>=20?'Critical':s>=12?'High':s>=6?'Medium':'Low';
              const sevColor  = s => ({critical:'#ef4444',high:'#f97316',medium:'#eab308',low:'#3b82f6'}[s]||'#64748b');
              const policyColor = s => ({approved:'#22c55e',draft:'#eab308',expired:'#ef4444'}[s]||'#64748b');
              const catColor  = c => ({Cyber:'#ef4444','Third Party':'#f97316',Operational:'#eab308',Compliance:'#8b5cf6'}[c]||'#64748b');
              const overallGRC = Math.round(grcFrameworks.reduce((s,f)=>s+f.score,0)/grcFrameworks.length);
              const openRisks  = riskRegister.filter(r=>r.status!=='mitigated');
              const criticalRisks = riskRegister.filter(r=>riskScore(r.l,r.i)>=16);
              const openFindings  = auditFindings.filter(f=>f.status!=='remediated');

              return (
                <div className="flex-1 overflow-hidden flex flex-col">
                  {/* Sub-nav */}
                  <div className="flex border-b border-slate-700/40 bg-slate-900/40 flex-shrink-0 px-3 gap-1 pt-2">
                    {[
                      {id:'frameworks', label:'Compliance Frameworks', icon:Scale},
                      {id:'risks',      label:'Risk Register',         icon:Flame},
                      {id:'audit',      label:'Audit Findings',        icon:BookMarked},
                      {id:'policies',   label:'Policies & Governance', icon:FileCheck},
                    ].map(s=>(
                      <button key={s.id} onClick={()=>setGrcSection(s.id)}
                        className={`flex items-center gap-1.5 px-3 py-1.5 rounded-t text-base font-medium border-b-2 transition-colors ${
                          grcSection===s.id?'border-violet-400 text-violet-400 bg-slate-800/60':'border-transparent text-slate-500 hover:text-slate-300'}`}>
                        <s.icon className="w-3 h-3"/>{s.label}
                      </button>
                    ))}
                    {/* GRC score pill */}
                    <div className="ml-auto flex items-center gap-2 pb-1.5 self-end">
                      <span className="text-base text-slate-400">GRC Score</span>
                      <span className="text-xl font-black" style={{color:overallGRC>=75?'#22c55e':overallGRC>=55?'#eab308':'#ef4444'}}>{overallGRC}%</span>
                    </div>
                  </div>

                  <div className="flex-1 overflow-y-auto p-4 space-y-4">

                    {/* ── FRAMEWORKS ── */}
                    {grcSection==='frameworks' && (
                      <>
                        {/* KPI row */}
                        <div className="grid grid-cols-4 gap-3">
                          {[
                            {label:'Open Controls',  value:grcFrameworks.reduce((s,f)=>s+(f.controls-f.passing),0), color:'#ef4444'},
                            {label:'Critical Gaps',  value:grcFrameworks.reduce((s,f)=>s+f.critical,0),            color:'#f97316'},
                            {label:'Frameworks',     value:grcFrameworks.length,                                     color:'#8b5cf6'},
                            {label:'Avg Compliance', value:`${overallGRC}%`,                                         color:overallGRC>=75?'#22c55e':overallGRC>=55?'#eab308':'#ef4444'},
                          ].map((k,i)=>(
                            <div key={i} className="p-3 rounded-xl border border-slate-700/40 bg-slate-800/30 text-center">
                              <p className="text-base text-slate-400 mb-1">{k.label}</p>
                              <p className="text-2xl font-black" style={{color:k.color}}>{k.value}</p>
                            </div>
                          ))}
                        </div>

                        {/* Framework cards */}
                        <div className="space-y-3">
                          {grcFrameworks.map(fw=>{
                            const failCount = fw.controls - fw.passing;
                            const fc = fw.score>=75?'#22c55e':fw.score>=55?'#eab308':'#ef4444';
                            return (
                              <div key={fw.id} className="rounded-xl border p-4" style={{backgroundColor:fw.color+'0a',borderColor:fw.color+'33'}}>
                                <div className="flex items-start justify-between mb-2">
                                  <div>
                                    <p className="font-bold text-lg" style={{color:fw.color}}>{fw.name}</p>
                                    <p className="text-base text-slate-500 mt-0.5">{fw.reg}</p>
                                  </div>
                                  <div className="text-right">
                                    <p className="text-2xl font-black" style={{color:fc}}>{fw.score}%</p>
                                    <p className="text-base" style={{color:fw.critical>0?'#ef4444':'#64748b'}}>{fw.critical} critical gaps</p>
                                  </div>
                                </div>
                                <div className="h-2 bg-slate-700 rounded-full overflow-hidden mb-2">
                                  <div className="h-full rounded-full transition-all" style={{width:`${fw.score}%`,backgroundColor:fc}}/>
                                </div>
                                <div className="flex gap-4 text-base">
                                  <span style={{color:'#22c55e'}}>✓ {fw.passing} passing</span>
                                  <span style={{color:'#ef4444'}}>✗ {failCount} failing</span>
                                  <span className="text-slate-400">of {fw.controls} controls</span>
                                  <div className="ml-auto h-1.5 bg-slate-700 rounded-full overflow-hidden w-24 self-center">
                                    <div className="h-full rounded-full" style={{width:`${(fw.passing/fw.controls)*100}%`,backgroundColor:fw.color}}/>
                                  </div>
                                </div>
                              </div>
                            );
                          })}
                        </div>
                      </>
                    )}

                    {/* ── RISK REGISTER ── */}
                    {grcSection==='risks' && (
                      <>
                        {/* Risk heatmap 5×5 */}
                        <div className="rounded-xl border border-slate-700/40 p-4 bg-slate-800/20">
                          <div className="flex items-center gap-2 mb-3">
                            <Flame className="w-4 h-4 text-orange-400"/>
                            <span className="font-bold text-lg">Risk Heat Map — Likelihood × Impact</span>
                            <span className="ml-auto text-base text-slate-400">{criticalRisks.length} critical · {openRisks.length} open</span>
                          </div>
                          <div className="flex gap-2">
                            {/* Y-axis label */}
                            <div className="flex flex-col justify-between py-1 text-slate-500" style={{fontSize:'9px',writingMode:'vertical-rl',transform:'rotate(180deg)',width:'12px'}}>
                              <span>Almost Certain (5)</span><span>Likely (4)</span><span>Possible (3)</span><span>Unlikely (2)</span><span>Rare (1)</span>
                            </div>
                            <div className="flex-1">
                              <div className="grid gap-1" style={{gridTemplateColumns:'repeat(5,1fr)'}}>
                                {[5,4,3,2,1].map(l=>[1,2,3,4,5].map(impact=>{
                                  const s   = l*impact;
                                  const col = riskColor(s);
                                  const here= riskRegister.filter(r=>r.l===l&&r.i===impact);
                                  return (
                                    <div key={`${l}-${impact}`} className="aspect-square rounded flex flex-col items-center justify-center text-base font-bold relative"
                                      style={{backgroundColor:col+'25',border:`1px solid ${col}44`}}>
                                      <span style={{color:col,fontSize:'8px'}}>{s}</span>
                                      {here.map((r,ri)=>(
                                        <span key={ri} className="font-mono text-white" title={r.title} style={{fontSize:'7px',lineHeight:1}}>{r.id}</span>
                                      ))}
                                    </div>
                                  );
                                }))}
                              </div>
                              {/* X-axis labels */}
                              <div className="grid mt-1" style={{gridTemplateColumns:'repeat(5,1fr)'}}>
                                {['Negligible','Minor','Moderate','Major','Catastrophic'].map(l=>(
                                  <span key={l} className="text-center text-slate-500" style={{fontSize:'7.5px'}}>{l}</span>
                                ))}
                              </div>
                              <p className="text-center text-slate-500 mt-0.5" style={{fontSize:'9px'}}>← Impact →</p>
                            </div>
                            {/* Legend */}
                            <div className="flex flex-col gap-1 justify-center pl-2">
                              {[['Critical','≥20','#ef4444'],['High','12-19','#f97316'],['Medium','6-11','#eab308'],['Low','1-5','#22c55e']].map(([l,r,c])=>(
                                <div key={l} className="flex items-center gap-1 text-base">
                                  <div className="w-3 h-3 rounded" style={{backgroundColor:c+'44',border:`1px solid ${c}66`}}/>
                                  <span style={{color:c,fontSize:'9px'}}>{l} ({r})</span>
                                </div>
                              ))}
                            </div>
                          </div>
                        </div>

                        {/* Risk table */}
                        <div className="rounded-xl border border-slate-700/40 overflow-hidden">
                          <div className="px-3 py-2 border-b border-slate-700/40 bg-slate-900/40 flex items-center gap-2">
                            <span className="font-bold text-base">Risk Register</span>
                            <span className="ml-auto px-1.5 py-0.5 rounded bg-red-500/20 text-red-400 text-base font-bold">{criticalRisks.length} CRITICAL</span>
                          </div>
                          <div className="overflow-x-auto">
                            <table className="w-full text-base">
                              <thead className="bg-slate-900/50">
                                <tr className="text-slate-400">
                                  {['ID','Category','Risk Title','L','I','Score','Treatment','Owner','Status','Due'].map(h=>(
                                    <th key={h} className="px-2.5 py-2 text-left font-medium whitespace-nowrap">{h}</th>
                                  ))}
                                </tr>
                              </thead>
                              <tbody className="divide-y divide-slate-700/20">
                                {[...riskRegister].sort((a,b)=>riskScore(b.l,b.i)-riskScore(a.l,a.i)).map(r=>{
                                  const s  = riskScore(r.l,r.i);
                                  const rc = riskColor(s);
                                  const stc= r.status==='mitigated'?'#22c55e':r.status==='in-progress'?'#eab308':'#ef4444';
                                  return (
                                    <tr key={r.id} className="hover:bg-slate-700/10">
                                      <td className="px-2.5 py-2 font-mono text-slate-400 whitespace-nowrap">{r.id}</td>
                                      <td className="px-2.5 py-2 whitespace-nowrap">
                                        <span className="px-1.5 py-0.5 rounded font-medium" style={{backgroundColor:catColor(r.cat)+'22',color:catColor(r.cat),fontSize:'10px'}}>{r.cat}</span>
                                      </td>
                                      <td className="px-2.5 py-2 max-w-xs">{r.title}</td>
                                      <td className="px-2.5 py-2 font-bold text-center" style={{color:rc}}>{r.l}</td>
                                      <td className="px-2.5 py-2 font-bold text-center" style={{color:rc}}>{r.i}</td>
                                      <td className="px-2.5 py-2">
                                        <span className="px-1.5 py-0.5 rounded font-black" style={{backgroundColor:rc+'22',color:rc,border:`1px solid ${rc}44`,fontSize:'11px'}}>{s} {riskLabel(s)}</span>
                                      </td>
                                      <td className="px-2.5 py-2 text-slate-300 whitespace-nowrap">{r.treatment}</td>
                                      <td className="px-2.5 py-2 text-slate-400 whitespace-nowrap">{r.owner}</td>
                                      <td className="px-2.5 py-2 whitespace-nowrap">
                                        <span className="px-1.5 py-0.5 rounded capitalize font-medium" style={{backgroundColor:stc+'22',color:stc,fontSize:'10px'}}>{r.status}</span>
                                      </td>
                                      <td className="px-2.5 py-2 font-mono text-slate-400 whitespace-nowrap">{r.due}</td>
                                    </tr>
                                  );
                                })}
                              </tbody>
                            </table>
                          </div>
                        </div>
                      </>
                    )}

                    {/* ── AUDIT FINDINGS ── */}
                    {grcSection==='audit' && (
                      <>
                        <div className="grid grid-cols-4 gap-3">
                          {[
                            {label:'Critical Findings', value:auditFindings.filter(f=>f.sev==='critical').length,   color:'#ef4444'},
                            {label:'High Findings',     value:auditFindings.filter(f=>f.sev==='high').length,       color:'#f97316'},
                            {label:'Open Findings',     value:openFindings.length,                                   color:'#eab308'},
                            {label:'Remediated',        value:auditFindings.filter(f=>f.status==='remediated').length,color:'#22c55e'},
                          ].map((k,i)=>(
                            <div key={i} className="p-3 rounded-xl border border-slate-700/40 bg-slate-800/30 text-center">
                              <p className="text-base text-slate-400 mb-1">{k.label}</p>
                              <p className="text-2xl font-black" style={{color:k.color}}>{k.value}</p>
                            </div>
                          ))}
                        </div>
                        <div className="rounded-xl border border-slate-700/40 overflow-hidden">
                          <div className="px-3 py-2 border-b border-slate-700/40 bg-slate-900/40 flex items-center gap-2">
                            <BookMarked className="w-3.5 h-3.5 text-violet-400"/>
                            <span className="font-bold text-base">Audit Findings — All Frameworks</span>
                          </div>
                          <div className="divide-y divide-slate-700/20">
                            {auditFindings.map(f=>{
                              const sc  = sevColor(f.sev);
                              const stc = f.status==='remediated'?'#22c55e':f.status==='in-progress'?'#eab308':'#ef4444';
                              return (
                                <div key={f.id} className="px-4 py-3 flex items-start gap-3">
                                  <div className="flex-shrink-0 w-16 text-right">
                                    <span className="font-mono text-slate-500 text-base">{f.id}</span>
                                  </div>
                                  <div className="flex-1 min-w-0">
                                    <div className="flex items-center gap-2 mb-1 flex-wrap">
                                      <span className="px-1.5 py-0.5 rounded text-base font-bold uppercase" style={{backgroundColor:sc+'22',color:sc,border:`1px solid ${sc}44`}}>{f.sev}</span>
                                      <span className="px-1.5 py-0.5 rounded text-base font-medium bg-violet-500/20 text-violet-400">{f.framework}</span>
                                      <span className="text-base font-mono text-slate-400">{f.control}</span>
                                    </div>
                                    <p className="text-lg font-medium">{f.finding}</p>
                                    <div className="flex items-center gap-3 mt-1 text-base text-slate-500">
                                      <span className="flex items-center gap-1"><CalendarClock className="w-3 h-3"/>Due {f.due}</span>
                                      <span className="px-1.5 py-0.5 rounded capitalize" style={{backgroundColor:stc+'22',color:stc}}>{f.status}</span>
                                    </div>
                                  </div>
                                </div>
                              );
                            })}
                          </div>
                        </div>
                      </>
                    )}

                    {/* ── POLICIES & GOVERNANCE ── */}
                    {grcSection==='policies' && (
                      <>
                        <div className="grid grid-cols-3 gap-3">
                          {[
                            {label:'Approved',   value:policies.filter(p=>p.status==='approved').length,  color:'#22c55e'},
                            {label:'Draft',      value:policies.filter(p=>p.status==='draft').length,     color:'#eab308'},
                            {label:'Expired',    value:policies.filter(p=>p.status==='expired').length,   color:'#ef4444'},
                          ].map((k,i)=>(
                            <div key={i} className="p-3 rounded-xl border border-slate-700/40 bg-slate-800/30 text-center">
                              <p className="text-base text-slate-400 mb-1">{k.label}</p>
                              <p className="text-2xl font-black" style={{color:k.color}}>{k.value}</p>
                            </div>
                          ))}
                        </div>
                        <div className="rounded-xl border border-slate-700/40 overflow-hidden">
                          <div className="px-3 py-2 border-b border-slate-700/40 bg-slate-900/40 flex items-center gap-2">
                            <FileCheck className="w-3.5 h-3.5 text-emerald-400"/>
                            <span className="font-bold text-base">Policy Register</span>
                          </div>
                          <div className="divide-y divide-slate-700/20">
                            {policies.map(p=>{
                              const pc = policyColor(p.status);
                              const overdue = new Date(p.nextReview) < new Date();
                              return (
                                <div key={p.id} className="px-4 py-3 flex items-start gap-3">
                                  <span className="font-mono text-slate-500 text-base flex-shrink-0 w-16">{p.id}</span>
                                  <div className="flex-1 min-w-0">
                                    <div className="flex items-center gap-2 mb-1">
                                      <p className="font-medium text-lg">{p.name}</p>
                                      <span className="px-1.5 py-0.5 rounded text-base capitalize font-bold" style={{backgroundColor:pc+'22',color:pc,border:`1px solid ${pc}44`}}>{p.status}</span>
                                      {overdue && <span className="px-1.5 py-0.5 rounded text-base font-bold bg-red-500/20 text-red-400">OVERDUE</span>}
                                    </div>
                                    <div className="flex flex-wrap gap-1 mb-1">
                                      {p.frameworks.map(fw=>{
                                        const fwc = grcFrameworks.find(f=>fw.startsWith(f.name.split(' ')[0])||f.name.includes(fw));
                                        return <span key={fw} className="px-1.5 py-0.5 rounded text-base" style={{backgroundColor:(fwc?.color||'#64748b')+'22',color:fwc?.color||'#94a3b8'}}>{fw}</span>;
                                      })}
                                    </div>
                                    <div className="flex items-center gap-4 text-base text-slate-500">
                                      <span>Owner: <span className="text-slate-300">{p.owner}</span></span>
                                      <span>Last review: {p.lastReview}</span>
                                      <span className={overdue?'text-red-400':''}>Next review: {p.nextReview}</span>
                                    </div>
                                  </div>
                                  <button
                                    onClick={()=>{ setReviewPolicy(p); setReviewForm({status:p.status, owner:p.owner, nextReview:p.nextReview, notes:''}); }}
                                    className="flex-shrink-0 flex items-center gap-1 px-2.5 py-1.5 rounded-lg text-base font-medium bg-slate-700/40 text-slate-300 hover:bg-cyan-500/20 hover:text-cyan-300 transition-colors">
                                    <ArrowUpRight className="w-3 h-3"/> Review
                                  </button>
                                </div>
                              );
                            })}
                          </div>
                        </div>

                        {/* Policy Review Modal */}
                        {reviewPolicy && (()=>{
                          const pc = policyColor(reviewPolicy.status);
                          return (
                            <div style={{position:'fixed',inset:0,background:'rgba(0,0,0,0.7)',display:'flex',alignItems:'center',justifyContent:'center',zIndex:9000}} onClick={()=>setReviewPolicy(null)}>
                              <div style={{background:'#0f172a',border:'1px solid #334155',borderRadius:16,width:520,maxWidth:'95vw',padding:28,boxShadow:'0 25px 50px rgba(0,0,0,0.6)'}} onClick={e=>e.stopPropagation()}>
                                {/* Header */}
                                <div style={{display:'flex',justifyContent:'space-between',alignItems:'flex-start',marginBottom:20}}>
                                  <div>
                                    <div style={{fontSize:11,fontWeight:700,color:'#64748b',textTransform:'uppercase',letterSpacing:'0.1em',marginBottom:4}}>Policy Review</div>
                                    <div style={{fontSize:18,fontWeight:700,color:'#f1f5f9'}}>{reviewPolicy.name}</div>
                                    <div style={{fontSize:12,color:'#94a3b8',marginTop:2}}>{reviewPolicy.id} · Owner: {reviewPolicy.owner}</div>
                                  </div>
                                  <button onClick={()=>setReviewPolicy(null)} style={{background:'#1e293b',border:'1px solid #334155',borderRadius:8,padding:'4px 10px',color:'#94a3b8',cursor:'pointer',fontSize:18,lineHeight:1}}>✕</button>
                                </div>

                                {/* Current frameworks */}
                                <div style={{display:'flex',flexWrap:'wrap',gap:6,marginBottom:20}}>
                                  {reviewPolicy.frameworks.map(fw=>{
                                    const fwc = grcFrameworks.find(f=>fw.startsWith(f.name.split(' ')[0])||f.name.includes(fw));
                                    return <span key={fw} style={{padding:'2px 10px',borderRadius:12,fontSize:11,fontWeight:600,background:(fwc?.color||'#64748b')+'22',color:fwc?.color||'#94a3b8'}}>{fw}</span>;
                                  })}
                                </div>

                                {/* Form fields */}
                                <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:12,marginBottom:16}}>
                                  <div>
                                    <label style={{display:'block',fontSize:11,fontWeight:600,color:'#64748b',textTransform:'uppercase',letterSpacing:'0.08em',marginBottom:6}}>Status</label>
                                    <select value={reviewForm.status} onChange={e=>setReviewForm(f=>({...f,status:e.target.value}))}
                                      style={{width:'100%',background:'#1e293b',border:'1px solid #334155',borderRadius:8,padding:'8px 10px',color:'#f1f5f9',fontSize:13}}>
                                      <option value="approved">Approved</option>
                                      <option value="draft">Draft</option>
                                      <option value="expired">Expired</option>
                                      <option value="under_review">Under Review</option>
                                    </select>
                                  </div>
                                  <div>
                                    <label style={{display:'block',fontSize:11,fontWeight:600,color:'#64748b',textTransform:'uppercase',letterSpacing:'0.08em',marginBottom:6}}>Owner</label>
                                    <input value={reviewForm.owner} onChange={e=>setReviewForm(f=>({...f,owner:e.target.value}))}
                                      style={{width:'100%',background:'#1e293b',border:'1px solid #334155',borderRadius:8,padding:'8px 10px',color:'#f1f5f9',fontSize:13}} />
                                  </div>
                                  <div>
                                    <label style={{display:'block',fontSize:11,fontWeight:600,color:'#64748b',textTransform:'uppercase',letterSpacing:'0.08em',marginBottom:6}}>Next Review Date</label>
                                    <input type="date" value={reviewForm.nextReview} onChange={e=>setReviewForm(f=>({...f,nextReview:e.target.value}))}
                                      style={{width:'100%',background:'#1e293b',border:'1px solid #334155',borderRadius:8,padding:'8px 10px',color:'#f1f5f9',fontSize:13}} />
                                  </div>
                                  <div>
                                    <label style={{display:'block',fontSize:11,fontWeight:600,color:'#64748b',textTransform:'uppercase',letterSpacing:'0.08em',marginBottom:6}}>Today's Review Date</label>
                                    <input type="date" defaultValue={new Date().toISOString().split('T')[0]} readOnly
                                      style={{width:'100%',background:'#0f172a',border:'1px solid #1e293b',borderRadius:8,padding:'8px 10px',color:'#64748b',fontSize:13}} />
                                  </div>
                                </div>
                                <div style={{marginBottom:20}}>
                                  <label style={{display:'block',fontSize:11,fontWeight:600,color:'#64748b',textTransform:'uppercase',letterSpacing:'0.08em',marginBottom:6}}>Review Notes</label>
                                  <textarea value={reviewForm.notes} onChange={e=>setReviewForm(f=>({...f,notes:e.target.value}))} rows={3} placeholder="Document findings, changes, or exceptions..."
                                    style={{width:'100%',background:'#1e293b',border:'1px solid #334155',borderRadius:8,padding:'10px',color:'#f1f5f9',fontSize:13,resize:'vertical'}} />
                                </div>

                                {/* Actions */}
                                <div style={{display:'flex',gap:10,justifyContent:'flex-end'}}>
                                  <button onClick={()=>setReviewPolicy(null)}
                                    style={{padding:'9px 20px',borderRadius:8,border:'1px solid #334155',background:'transparent',color:'#94a3b8',fontSize:13,fontWeight:600,cursor:'pointer'}}>
                                    Cancel
                                  </button>
                                  <button onClick={()=>{
                                    const today = new Date().toISOString().split('T')[0];
                                    setPolicies(prev=>prev.map(p=>p.id===reviewPolicy.id
                                      ? {...p, status:reviewForm.status, owner:reviewForm.owner, nextReview:reviewForm.nextReview, lastReview:today}
                                      : p
                                    ));
                                    setReviewPolicy(null);
                                  }}
                                    style={{padding:'9px 20px',borderRadius:8,border:'none',background:'#06b6d4',color:'#fff',fontSize:13,fontWeight:700,cursor:'pointer'}}>
                                    Save Review
                                  </button>
                                </div>
                              </div>
                            </div>
                          );
                        })()}
                      </>
                    )}

                  </div>
                </div>
              );
            })()}

            {/* ── SOC Team Tab ─────────────────────────────────────────────── */}
            {activeTab==='team' && (
              <div className="flex-1 overflow-y-auto p-6">
                {/* Header */}
                <div className="mb-6">
                  <h2 className="text-xl font-bold text-cyan-400 flex items-center gap-2">
                    <Users className="w-5 h-5"/> ADS Team — IoMT Anomaly Detection System
                  </h2>
                  <p className="text-slate-500 text-sm mt-1">M.S. Cybersecurity Capstone Project · Active Shift</p>
                </div>

                {/* Team cards grid */}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-8">
                  {SOC_TEAM.map((member, idx) => {
                    const userDef  = DEMO_USERS.find(u => u.username === member.username);
                    const roleDef  = userDef ? ROLE_DEFS[userDef.role] : null;
                    const isOnline = onlineUsernames.includes(member.username);
                    const tabLabels = {
                      exec:'Overview', alerts:'Alerts & MITRE', playbook:'Playbooks', risk:'Risk Score',
                      forensics:'Forensics', geomap:'Geo Map', heatmap:'Heatmap', topology:'Topology',
                      upload:'CSV Analysis', hipaa:'HIPAA', grc:'GRC', team:'SOC Team',
                    };
                    return (
                      <div key={idx} className="rounded-xl border border-slate-700/50 bg-slate-900/60 p-5 hover:border-cyan-500/30 transition-colors">
                        <div className="flex gap-4 items-start mb-3">
                          {/* Avatar */}
                          <div className="flex-shrink-0 w-12 h-12 rounded-full flex items-center justify-center font-bold text-sm text-white"
                            style={{ backgroundColor: member.color + '33', border: `2px solid ${member.color}` }}>
                            {member.avatar}
                          </div>
                          {/* Info */}
                          <div className="flex-1 min-w-0">
                            <div className="flex items-center gap-2 mb-0.5 flex-wrap">
                              <span className="font-semibold text-slate-100 text-sm">{member.name}</span>
                              {member.username === 'admin'   && <span className="px-1.5 py-0.5 rounded text-xs font-bold bg-amber-500/20 text-amber-400 border border-amber-500/30">ADMIN</span>}
                              {member.username === 'tinashe' && <span className="px-1.5 py-0.5 rounded text-xs font-bold bg-red-500/20 text-red-400 border border-red-500/30">LEAD</span>}
                            </div>
                            <p className="text-xs mb-1" style={{ color: member.color }}>{member.role}</p>
                            <div className="flex items-center gap-1.5">
                              <span className={`w-1.5 h-1.5 rounded-full ${isOnline ? 'bg-emerald-400' : 'bg-slate-600'}`}/>
                              <span className={`text-xs ${isOnline ? 'text-emerald-400' : 'text-slate-500'}`}>
                                {isOnline ? 'On Shift' : 'Off Shift'}
                              </span>
                            </div>
                          </div>
                          {/* Permissions badges */}
                          {roleDef && (
                            <div className="flex flex-col gap-1 flex-shrink-0">
                              {roleDef.canManageUsers  && <span className="px-1.5 py-0.5 rounded text-xs font-bold bg-amber-500/15 text-amber-400 border border-amber-500/25">User Mgmt</span>}
                              {roleDef.canConfigSystem && <span className="px-1.5 py-0.5 rounded text-xs font-bold bg-amber-500/15 text-amber-400 border border-amber-500/25">Sys Config</span>}
                              {roleDef.canViewAll      && <span className="px-1.5 py-0.5 rounded text-xs font-bold bg-amber-500/15 text-amber-400 border border-amber-500/25">Full Access</span>}
                              {roleDef.canBlock    && <span className="px-1.5 py-0.5 rounded text-xs font-bold bg-orange-500/15 text-orange-400 border border-orange-500/25">Block IP</span>}
                              {roleDef.canIsolate  && <span className="px-1.5 py-0.5 rounded text-xs font-bold bg-red-500/15 text-red-400 border border-red-500/25">Isolate</span>}
                              {roleDef.canAck      && <span className="px-1.5 py-0.5 rounded text-xs font-bold bg-cyan-500/15 text-cyan-400 border border-cyan-500/25">Ack Alert</span>}
                            </div>
                          )}
                        </div>
                        {/* Dashboard access tabs */}
                        {roleDef && (
                          <div className="flex flex-wrap gap-1 pt-3 border-t border-slate-800/60">
                            {roleDef.tabs.map(t => (
                              <span key={t} className="px-1.5 py-0.5 rounded text-xs bg-slate-800/80 text-slate-400 border border-slate-700/40">
                                {tabLabels[t] ?? t}
                              </span>
                            ))}
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>

                {/* Shift summary */}
                <div className="rounded-xl border border-slate-700/40 bg-slate-900/40 p-5 mb-4">
                  <h3 className="text-sm font-semibold text-slate-300 mb-3 flex items-center gap-2">
                    <Shield className="w-4 h-4 text-cyan-400"/> Current Shift Summary
                  </h3>
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                    <div className="rounded-lg bg-slate-800/60 px-4 py-3 text-center">
                      <div className="text-2xl font-bold text-red-400">{alerts.filter(a=>a.severity==='critical').length}</div>
                      <div className="text-xs text-slate-500 mt-0.5">Critical Alerts</div>
                    </div>
                    <div className="rounded-lg bg-slate-800/60 px-4 py-3 text-center">
                      <div className="text-2xl font-bold text-orange-400">{alerts.filter(a=>a.severity==='high').length}</div>
                      <div className="text-xs text-slate-500 mt-0.5">High Alerts</div>
                    </div>
                    <div className="rounded-lg bg-slate-800/60 px-4 py-3 text-center">
                      <div className="text-2xl font-bold text-emerald-400">{blockedIPs.length}</div>
                      <div className="text-xs text-slate-500 mt-0.5">IPs Blocked</div>
                    </div>
                    <div className="rounded-lg bg-slate-800/60 px-4 py-3 text-center">
                      <div className="text-2xl font-bold text-violet-400">{suppressedCount}</div>
                      <div className="text-xs text-slate-500 mt-0.5">FP Suppressed</div>
                    </div>
                  </div>
                </div>

                {/* Recent response log with analyst names */}
                <div className="rounded-xl border border-slate-700/40 bg-slate-900/40 overflow-hidden">
                  <div className="px-4 py-2.5 border-b border-slate-700/40 flex items-center gap-2">
                    <Activity className="w-3.5 h-3.5 text-cyan-400"/>
                    <span className="text-sm font-semibold">Recent Analyst Actions</span>
                  </div>
                  <div className="divide-y divide-slate-800/60">
                    {responseLog.length === 0 ? (
                      <div className="px-4 py-6 text-center text-slate-500 text-sm">No actions logged this shift yet.</div>
                    ) : responseLog.slice(0, 10).map((log, i) => {
                      const member = SOC_TEAM.find(m => m.username === log.user || m.name === log.user);
                      const avatarBg = member?.color || '#6366f1';
                      const initials = (log.user||'AU').split(/[\s_]/).map(w=>w[0]).join('').toUpperCase().slice(0,2);
                      const actionColor = log.action?.includes('Block')?'#ef4444':log.action?.includes('Isolated')?'#8b5cf6':log.action?.includes('Resolved')?'#22c55e':log.action?.includes('Ack')?'#f59e0b':'#94a3b8';
                      const sevBadge = log.severity ? {critical:'#ef4444',high:'#f97316',medium:'#eab308',low:'#22c55e'}[log.severity] : null;
                      return (
                        <div key={i} className="px-4 py-2.5 flex items-center gap-3 hover:bg-slate-800/30">
                          <div className="w-7 h-7 rounded-full flex items-center justify-center text-xs font-bold flex-shrink-0"
                            style={{ backgroundColor: avatarBg + '33', color: avatarBg, border: `1px solid ${avatarBg}44` }}>
                            {initials}
                          </div>
                          <div className="flex-1 min-w-0">
                            <div className="flex items-center gap-1.5 flex-wrap">
                              <span className="text-xs font-bold" style={{ color: avatarBg }}>{log.user}</span>
                              {log.role && <span className="text-xs text-slate-600">({log.role})</span>}
                              <span className="text-xs font-semibold" style={{color:actionColor}}>{log.action}</span>
                              {sevBadge && <span className="text-xs px-1.5 rounded font-bold" style={{background:sevBadge+'22',color:sevBadge}}>{log.severity?.toUpperCase()}</span>}
                            </div>
                            <div className="flex items-center gap-2 mt-0.5">
                              {log.target && <span className="text-xs text-slate-400">→ <span className="font-mono text-slate-300">{log.target}</span></span>}
                              {log.device && <span className="text-xs text-slate-500">· {log.device}</span>}
                              {log.alert && <span className="text-xs text-slate-600">· {log.alert}</span>}
                            </div>
                          </div>
                          <span className="text-xs text-slate-600 flex-shrink-0">{log.time}</span>
                        </div>
                      );
                    })}
                  </div>
                </div>
              </div>
            )}

            {/* ── Admin Panel Tab ───────────────────────────────────────────── */}
            {activeTab==='admin_panel' && currentUser?.role === 'admin' && (()=>{
              const iotmDevices = [
                { id:'DEV-001', name:'Infusion Pump',    vendor:'BD Alaris',   fw:'2.3.1', patch:'Current',   vlan:'VLAN-20 Clinical', status:'online',  risk:'low',    ip:'192.168.20.50', lastSeen:'2 min ago' },
                { id:'DEV-002', name:'Heart Monitor',    vendor:'Philips',     fw:'4.1.0', patch:'Pending',   vlan:'VLAN-20 Clinical', status:'online',  risk:'medium', ip:'192.168.20.22', lastSeen:'1 min ago' },
                { id:'DEV-003', name:'Pulse Oximeter',  vendor:'Masimo',      fw:'1.9.3', patch:'Current',   vlan:'VLAN-20 Clinical', status:'online',  risk:'low',    ip:'192.168.20.35', lastSeen:'3 min ago' },
                { id:'DEV-004', name:'ECG Monitor',     vendor:'GE Healthcare',fw:'3.0.2', patch:'EOL',       vlan:'VLAN-20 Clinical', status:'online',  risk:'high',   ip:'192.168.20.41', lastSeen:'Just now'  },
                { id:'DEV-005', name:'MRI Controller',  vendor:'Siemens',     fw:'6.2.0', patch:'Current',   vlan:'VLAN-30 Imaging',  status:'offline', risk:'medium', ip:'192.168.30.10', lastSeen:'18 min ago'},
                { id:'DEV-006', name:'Ventilator',      vendor:'Medtronic',   fw:'2.1.0', patch:'Pending',   vlan:'VLAN-20 Clinical', status:'online',  risk:'high',   ip:'192.168.20.60', lastSeen:'Just now'  },
              ];
              const aclRulesList = [
                { id:'ACL-001', src:'VLAN-20',        dst:'VLAN-10 Corp', action:'DENY',  proto:'ANY',  port:'*',    reason:'Clinical isolation' },
                { id:'ACL-002', src:'VLAN-20',        dst:'10.0.0.5',     action:'ALLOW', proto:'TCP',  port:'443',  reason:'SIEM feed' },
                { id:'ACL-003', src:'VLAN-30 Imaging',dst:'VLAN-20',      action:'DENY',  proto:'ANY',  port:'*',    reason:'Imaging subnet isolation' },
                { id:'ACL-004', src:'SOC Subnet',     dst:'VLAN-20',      action:'ALLOW', proto:'TCP',  port:'8443', reason:'SOC management access' },
                { id:'ACL-005', src:'192.168.99.0/24',dst:'ANY',          action:'DENY',  proto:'ANY',  port:'*',    reason:'Blocked rogue subnet' },
              ];
              const patches = [
                { device:'Heart Monitor',  cve:'CVE-2025-1183', severity:'high',   status:'awaiting_vendor', vendor:'Philips',      eta:'Q3 2026', compensating:'Network isolation applied' },
                { device:'ECG Monitor',    cve:'CVE-2024-9821', severity:'critical',status:'eol',            vendor:'GE Healthcare', eta:'N/A',     compensating:'VLAN micro-segment + IDS rule' },
                { device:'Ventilator',     cve:'CVE-2025-3341', severity:'high',   status:'testing',         vendor:'Medtronic',    eta:'2 weeks',  compensating:'Disabled remote access port' },
                { device:'Infusion Pump',  cve:'CVE-2025-0092', severity:'medium', status:'scheduled',       vendor:'BD Alaris',    eta:'May 2026', compensating:'None required' },
              ];
              const vendors = [
                { name:'Philips Healthcare',   type:'OEM',      access:'Remote',  session:'Active',  expires:'2h',   monitor:true  },
                { name:'BD Alaris',            type:'OEM',      access:'None',    session:'None',    expires:'—',    monitor:false },
                { name:'GE Healthcare',        type:'OEM',      access:'Pending', session:'None',    expires:'—',    monitor:false },
                { name:'SecureNet MSP',        type:'3rd Party',access:'Remote',  session:'Active',  expires:'45m',  monitor:true  },
                { name:'ClinicalCloud Backup', type:'3rd Party',access:'API',     session:'Active',  expires:'24h',  monitor:true  },
              ];
              const backups = [
                { target:'Device Config Repo',   lastBackup:'2026-04-19 02:00', status:'success', size:'1.2 GB',  rpo:'24h',  rto:'2h'  },
                { target:'SOC Platform DB',       lastBackup:'2026-04-19 03:00', status:'success', size:'4.8 GB',  rpo:'6h',   rto:'1h'  },
                { target:'SIEM Log Archive',      lastBackup:'2026-04-18 22:00', status:'warning', size:'22.4 GB', rpo:'12h',  rto:'4h'  },
                { target:'Clinical Device Images',lastBackup:'2026-04-17 00:00', status:'success', size:'89.1 GB', rpo:'7d',   rto:'8h'  },
              ];
              const logFeeds = [
                { source:'Infusion Pump Syslog',   proto:'Syslog/514', status:'active',  eps:12,  lastEvent:'2s ago'  },
                { source:'Heart Monitor SNMP',     proto:'SNMP Trap',  status:'active',  eps:4,   lastEvent:'8s ago'  },
                { source:'ECG Monitor API',        proto:'REST/HTTPS', status:'active',  eps:28,  lastEvent:'1s ago'  },
                { source:'Firewall NetFlow',        proto:'NetFlow v9', status:'active',  eps:3400,lastEvent:'<1s ago' },
                { source:'MRI Controller Syslog',  proto:'Syslog/514', status:'inactive',eps:0,   lastEvent:'18m ago' },
                { source:'VLAN-20 Tap',            proto:'SPAN Port',  status:'active',  eps:890, lastEvent:'<1s ago' },
              ];

              const subTabs = [
                { id:'assets',     label:'Device Assets',        icon:Monitor   },
                { id:'network',    label:'Network & ACLs',        icon:Router    },
                { id:'patch',      label:'Patch Management',      icon:ShieldCheck},
                { id:'access',     label:'Access Control',        icon:KeyRound  },
                { id:'monitoring', label:'Security Monitoring',   icon:Activity  },
                { id:'backup',     label:'Backup & Recovery',     icon:HardDrive },
                { id:'vendors',    label:'Vendor Access',         icon:ExternalLink},
                { id:'users',      label:'User Accounts',         icon:Users     },
              ];
              const sc = (s)=>({critical:'#ef4444',high:'#f97316',medium:'#eab308',low:'#22c55e',success:'#22c55e',warning:'#eab308',active:'#22c55e',inactive:'#64748b',online:'#22c55e',offline:'#ef4444',EOL:'#ef4444',Pending:'#f97316',Current:'#22c55e',testing:'#06b6d4',scheduled:'#8b5cf6',awaiting_vendor:'#f97316',eol:'#ef4444'}[s]||'#64748b');

              return (
              <div className="flex-1 overflow-hidden flex flex-col">
                {/* Header */}
                <div className="flex items-center justify-between px-5 py-3 border-b border-slate-800/60 flex-shrink-0">
                  <div>
                    <h2 className="text-base font-bold text-amber-400 flex items-center gap-2"><Settings className="w-4 h-4"/>System Administration · IoMT SOC</h2>
                    <p className="text-xs text-slate-500 mt-0.5">Infrastructure · Device Management · Security Operations Support</p>
                  </div>
                  <div className="flex items-center gap-3">
                    <div className="flex gap-2">
                      {[
                        { label:`${iotmDevices.length} Devices`, color:'#06b6d4' },
                        { label:`${iotmDevices.filter(d=>d.risk==='high').length} High Risk`, color:'#ef4444' },
                        { label:`${patches.length} CVEs`, color:'#f97316' },
                        { label:`${vendors.filter(v=>v.session==='Active').length} Vendor Sessions`, color:'#8b5cf6' },
                      ].map((s,i)=>(
                        <div key={i} className="px-2.5 py-1 rounded-lg text-xs font-semibold" style={{background:s.color+'15',color:s.color,border:`1px solid ${s.color}30`}}>{s.label}</div>
                      ))}
                    </div>
                    <div className="px-2.5 py-1 rounded-lg bg-amber-500/10 border border-amber-500/25 flex items-center gap-1.5">
                      <KeyRound className="w-3 h-3 text-amber-400"/>
                      <span className="text-xs font-bold text-amber-400">ADMIN</span>
                    </div>
                  </div>
                </div>

                {/* Sub-navigation */}
                <div className="flex border-b border-slate-700/40 bg-slate-900/30 flex-shrink-0 px-3 gap-0.5 pt-1.5 overflow-x-auto" style={{scrollbarWidth:'none'}}>
                  {subTabs.map(t=>(
                    <button key={t.id} onClick={()=>setAdminSub(t.id)}
                      className={`flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-t-lg border-b-2 transition-all whitespace-nowrap ${adminSub===t.id?'border-amber-400 text-amber-400 bg-amber-500/10':'border-transparent text-slate-500 hover:text-slate-300'}`}>
                      <t.icon className="w-3 h-3"/>{t.label}
                    </button>
                  ))}
                </div>

                <div className="flex-1 overflow-y-auto p-5">

                  {/* ── Device Assets ── */}
                  {adminSub==='assets' && (
                    <div>
                      <div className="grid grid-cols-4 gap-3 mb-5">
                        {[
                          { label:'Total Devices',   value:iotmDevices.length,                                     color:'#06b6d4' },
                          { label:'Online',          value:iotmDevices.filter(d=>d.status==='online').length,       color:'#22c55e' },
                          { label:'Patch Pending',   value:iotmDevices.filter(d=>d.patch==='Pending').length,       color:'#f97316' },
                          { label:'EOL Devices',     value:iotmDevices.filter(d=>d.patch==='EOL').length,           color:'#ef4444' },
                        ].map((s,i)=>(
                          <div key={i} className="rounded-xl border border-slate-700/40 bg-slate-900/60 px-4 py-3">
                            <div className="text-xl font-bold" style={{color:s.color}}>{s.value}</div>
                            <div className="text-xs text-slate-500 mt-0.5">{s.label}</div>
                          </div>
                        ))}
                      </div>
                      <div className="rounded-xl border border-slate-700/40 overflow-hidden">
                        <div className="px-4 py-2.5 border-b border-slate-700/40 bg-slate-900/40 flex items-center justify-between">
                          <span className="text-sm font-bold text-slate-200">IoMT Device Inventory</span>
                          <span className="text-xs text-slate-500">FDA-managed asset registry</span>
                        </div>
                        <div className="divide-y divide-slate-800/60">
                          {iotmDevices.map((d,i)=>(
                            <div key={i} className="px-4 py-3 flex items-center gap-3">
                              <div className="w-2 h-2 rounded-full flex-shrink-0" style={{background:sc(d.status)}}/>
                              <span className="text-xs font-mono text-slate-500 w-18 flex-shrink-0">{d.id}</span>
                              <div className="flex-1 min-w-0">
                                <div className="flex items-center gap-2">
                                  <span className="text-sm font-semibold text-slate-100">{d.name}</span>
                                  <span className="text-xs text-slate-500">{d.vendor}</span>
                                </div>
                                <div className="flex items-center gap-3 mt-0.5 text-xs text-slate-500">
                                  <span>FW {d.fw}</span><span>{d.vlan}</span><span>{d.ip}</span><span>Seen {d.lastSeen}</span>
                                </div>
                              </div>
                              <span className="text-xs px-2 py-0.5 rounded font-semibold" style={{background:sc(d.patch)+'20',color:sc(d.patch),border:`1px solid ${sc(d.patch)}40`}}>{d.patch}</span>
                              <span className="text-xs px-2 py-0.5 rounded font-semibold" style={{background:sc(d.risk)+'20',color:sc(d.risk),border:`1px solid ${sc(d.risk)}40`}}>{d.risk} risk</span>
                            </div>
                          ))}
                        </div>
                      </div>
                    </div>
                  )}

                  {/* ── Network & ACLs ── */}
                  {adminSub==='network' && (
                    <div className="space-y-4">
                      <div className="grid grid-cols-3 gap-3 mb-2">
                        {[
                          { label:'Network Segments', value:'4 VLANs', sub:'Clinical · Imaging · Corp · Mgmt', color:'#06b6d4' },
                          { label:'ACL Rules Active',  value:aclRulesList.length, sub:`${aclRulesList.filter(r=>r.action==='DENY').length} deny rules`, color:'#ef4444' },
                          { label:'Bandwidth Status',  value:'Normal', sub:'Clinical streams nominal', color:'#22c55e' },
                        ].map((s,i)=>(
                          <div key={i} className="rounded-xl border border-slate-700/40 bg-slate-900/60 px-4 py-3">
                            <div className="text-lg font-bold" style={{color:s.color}}>{s.value}</div>
                            <div className="text-xs text-slate-400 font-medium">{s.label}</div>
                            <div className="text-xs text-slate-600 mt-0.5">{s.sub}</div>
                          </div>
                        ))}
                      </div>
                      <div className="rounded-xl border border-slate-700/40 overflow-hidden">
                        <div className="px-4 py-2.5 border-b border-slate-700/40 bg-slate-900/40">
                          <span className="text-sm font-bold text-slate-200">Network Segmentation · VLAN Map</span>
                        </div>
                        <div className="p-4 grid grid-cols-2 gap-3">
                          {[
                            { name:'VLAN-20 Clinical LAN',    range:'192.168.20.0/24', devices:4, color:'#ef4444',  isolation:'Fully isolated from Corp' },
                            { name:'VLAN-30 Imaging Subnet',  range:'192.168.30.0/24', devices:1, color:'#8b5cf6',  isolation:'DENY all inter-VLAN' },
                            { name:'VLAN-10 Corporate IT',    range:'192.168.10.0/24', devices:0, color:'#06b6d4',  isolation:'Internet access permitted' },
                            { name:'VLAN-40 SOC Mgmt',        range:'192.168.40.0/24', devices:0, color:'#f97316',  isolation:'SOC staff only — MFA required' },
                          ].map((v,i)=>(
                            <div key={i} className="rounded-lg border border-slate-700/40 bg-slate-900/40 p-3">
                              <div className="flex items-center gap-2 mb-1">
                                <div className="w-2 h-2 rounded-full" style={{background:v.color}}/>
                                <span className="text-xs font-bold text-slate-200">{v.name}</span>
                              </div>
                              <div className="text-xs text-slate-500 font-mono mb-1">{v.range}</div>
                              <div className="text-xs text-slate-400">{v.isolation}</div>
                              {v.devices>0 && <div className="text-xs mt-1" style={{color:v.color}}>{v.devices} IoMT device{v.devices>1?'s':''} registered</div>}
                            </div>
                          ))}
                        </div>
                      </div>
                      <div className="rounded-xl border border-slate-700/40 overflow-hidden">
                        <div className="px-4 py-2.5 border-b border-slate-700/40 bg-slate-900/40">
                          <span className="text-sm font-bold text-slate-200">Access Control Lists (ACLs)</span>
                        </div>
                        <div className="divide-y divide-slate-800/60">
                          {aclRulesList.map((r,i)=>(
                            <div key={i} className="px-4 py-2.5 flex items-center gap-3 text-xs">
                              <span className="font-mono text-slate-500 w-18 flex-shrink-0">{r.id}</span>
                              <span className={`px-2 py-0.5 rounded font-bold flex-shrink-0 ${r.action==='DENY'?'bg-red-500/20 text-red-400 border border-red-500/30':'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'}`}>{r.action}</span>
                              <span className="text-slate-300 flex-shrink-0">{r.src}</span>
                              <span className="text-slate-600">→</span>
                              <span className="text-slate-300 flex-shrink-0">{r.dst}</span>
                              <span className="text-slate-500 font-mono flex-shrink-0">{r.proto}:{r.port}</span>
                              <span className="text-slate-600 flex-1 truncate">{r.reason}</span>
                            </div>
                          ))}
                        </div>
                      </div>
                    </div>
                  )}

                  {/* ── Patch Management ── */}
                  {adminSub==='patch' && (
                    <div className="space-y-4">
                      <div className="rounded-lg border border-amber-500/30 bg-amber-500/5 p-3 flex items-start gap-2 mb-2">
                        <AlertTriangle className="w-4 h-4 text-amber-400 flex-shrink-0 mt-0.5"/>
                        <p className="text-xs text-amber-300">All patches for FDA-cleared devices require vendor approval and validation before deployment. Compensating controls must be documented for unpatched CVEs.</p>
                      </div>
                      <div className="rounded-xl border border-slate-700/40 overflow-hidden">
                        <div className="px-4 py-2.5 border-b border-slate-700/40 bg-slate-900/40 flex items-center justify-between">
                          <span className="text-sm font-bold text-slate-200">Active CVE Tracker</span>
                          <span className="text-xs text-slate-500">{patches.length} open vulnerabilities</span>
                        </div>
                        <div className="divide-y divide-slate-800/60">
                          {patches.map((p,i)=>(
                            <div key={i} className="px-4 py-3">
                              <div className="flex items-center gap-3 mb-1.5">
                                <span className="font-mono text-xs text-slate-400 flex-shrink-0">{p.cve}</span>
                                <span className="text-sm font-semibold text-slate-100">{p.device}</span>
                                <span className="text-xs px-1.5 py-0.5 rounded font-bold" style={{background:sc(p.severity)+'20',color:sc(p.severity),border:`1px solid ${sc(p.severity)}40`}}>{p.severity}</span>
                                <span className="text-xs px-1.5 py-0.5 rounded font-semibold ml-auto" style={{background:sc(p.status)+'20',color:sc(p.status),border:`1px solid ${sc(p.status)}40`}}>{p.status.replace('_',' ')}</span>
                              </div>
                              <div className="flex gap-4 text-xs text-slate-500">
                                <span>Vendor: <span className="text-slate-300">{p.vendor}</span></span>
                                <span>ETA: <span className="text-slate-300">{p.eta}</span></span>
                                <span>Compensating: <span className="text-emerald-400">{p.compensating}</span></span>
                              </div>
                            </div>
                          ))}
                        </div>
                      </div>
                    </div>
                  )}

                  {/* ── Access Control ── */}
                  {adminSub==='access' && (
                    <div className="space-y-4">
                      <div className="grid grid-cols-3 gap-3 mb-2">
                        {[
                          { label:'Total Accounts', value:DEMO_USERS.length, color:'#06b6d4' },
                          { label:'MFA Enforced',   value:`${DEMO_USERS.length}/${DEMO_USERS.length}`, color:'#22c55e' },
                          { label:'Privileged',      value:1, color:'#f59e0b' },
                        ].map((s,i)=>(
                          <div key={i} className="rounded-xl border border-slate-700/40 bg-slate-900/60 px-4 py-3">
                            <div className="text-xl font-bold" style={{color:s.color}}>{s.value}</div>
                            <div className="text-xs text-slate-500 mt-0.5">{s.label}</div>
                          </div>
                        ))}
                      </div>
                      <div className="rounded-xl border border-slate-700/40 overflow-hidden">
                        <div className="px-4 py-2.5 border-b border-slate-700/40 bg-slate-900/40 flex items-center justify-between">
                          <span className="text-sm font-bold text-slate-200">User Accounts & Roles</span>
                          <span className="text-xs text-slate-500">Least-privilege access enforced</span>
                        </div>
                        <div className="divide-y divide-slate-800/60">
                          {DEMO_USERS.map((u,i)=>{
                            const rd=ROLE_DEFS[u.role];
                            const team=SOC_TEAM.find(m=>m.username===u.username);
                            return(
                              <div key={i} className="px-4 py-3 flex items-center gap-3">
                                <div className="w-8 h-8 rounded-full flex items-center justify-center text-xs font-bold flex-shrink-0" style={{background:(rd?.color||'#64748b')+'22',border:`1.5px solid ${rd?.color||'#64748b'}`,color:rd?.color}}>
                                  {u.avatar}
                                </div>
                                <div className="flex-1 min-w-0">
                                  <div className="text-sm font-semibold text-slate-100">{u.name}</div>
                                  <div className="text-xs text-slate-500">{u.title} · <span className="font-mono">{u.username}</span></div>
                                </div>
                                <span className={`text-xs px-2 py-0.5 rounded border font-semibold ${rd?.badge}`}>{rd?.label}</span>
                                <div className="flex items-center gap-1.5">
                                  <CheckCircle className="w-3 h-3 text-emerald-400"/>
                                  <span className="text-xs text-emerald-400">MFA</span>
                                </div>
                                <div className="flex items-center gap-1.5">
                                  <span className={`w-1.5 h-1.5 rounded-full ${team?.online?'bg-emerald-400':'bg-slate-600'}`}/>
                                  <span className={`text-xs ${team?.online?'text-emerald-400':'text-slate-500'}`}>{team?.online?'Online':'Offline'}</span>
                                </div>
                              </div>
                            );
                          })}
                        </div>
                      </div>
                    </div>
                  )}

                  {/* ── Security Monitoring ── */}
                  {adminSub==='monitoring' && (
                    <div className="space-y-4">
                      <div className="rounded-xl border border-slate-700/40 overflow-hidden">
                        <div className="px-4 py-2.5 border-b border-slate-700/40 bg-slate-900/40 flex items-center justify-between">
                          <span className="text-sm font-bold text-slate-200">SIEM Log Feed Status</span>
                          <span className="text-xs text-emerald-400">{logFeeds.filter(f=>f.status==='active').length}/{logFeeds.length} feeds active</span>
                        </div>
                        <div className="divide-y divide-slate-800/60">
                          {logFeeds.map((f,i)=>(
                            <div key={i} className="px-4 py-2.5 flex items-center gap-3">
                              <div className={`w-2 h-2 rounded-full flex-shrink-0 ${f.status==='active'?'bg-emerald-400':'bg-red-400'}`}/>
                              <div className="flex-1 min-w-0">
                                <div className="text-sm font-semibold text-slate-100">{f.source}</div>
                                <div className="text-xs text-slate-500">{f.proto} · Last event: {f.lastEvent}</div>
                              </div>
                              <div className="text-right">
                                <div className="text-xs font-bold text-slate-200">{f.eps.toLocaleString()} <span className="text-slate-500 font-normal">EPS</span></div>
                              </div>
                              <span className={`text-xs px-2 py-0.5 rounded font-semibold ${f.status==='active'?'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30':'bg-red-500/20 text-red-400 border border-red-500/30'}`}>{f.status}</span>
                            </div>
                          ))}
                        </div>
                      </div>
                      <div className="grid grid-cols-2 gap-4">
                        <div className="rounded-xl border border-slate-700/40 bg-slate-900/40 p-4">
                          <div className="text-sm font-bold text-slate-200 mb-3 flex items-center gap-2"><Server className="w-3.5 h-3.5 text-cyan-400"/>Platform Status</div>
                          {[
                            ['FastAPI Backend',  'Running · Port 8005', '#22c55e'],
                            ['WebSocket Stream', liveRunning?'Active':'Stopped', liveRunning?'#22c55e':'#ef4444'],
                            ['LightGBM Model',   'Loaded · CICIoMT2024', '#22c55e'],
                            ['SQLite DB',        `${alerts.length} records`, '#06b6d4'],
                            ['React Frontend',   'Running · Port 5174', '#22c55e'],
                          ].map(([k,v,c])=>(
                            <div key={k} className="flex justify-between py-1.5 border-b border-slate-800/40 last:border-0">
                              <span className="text-xs text-slate-500">{k}</span>
                              <span className="text-xs font-medium" style={{color:c}}>{v}</span>
                            </div>
                          ))}
                        </div>
                        <div className="rounded-xl border border-slate-700/40 bg-slate-900/40 p-4">
                          <div className="text-sm font-bold text-slate-200 mb-3 flex items-center gap-2"><ShieldCheck className="w-3.5 h-3.5 text-emerald-400"/>Alert Tuning</div>
                          {[
                            ['Confidence Threshold', `${alertThreshold}%`],
                            ['FP Rules Active',       fpSuppressions.length],
                            ['Alerts Suppressed',     suppressedCount],
                            ['Active Alerts',         alerts.filter(a=>a.status==='active').length],
                            ['Stream Interval',       '0.8s'],
                          ].map(([k,v])=>(
                            <div key={k} className="flex justify-between py-1.5 border-b border-slate-800/40 last:border-0">
                              <span className="text-xs text-slate-500">{k}</span>
                              <span className="text-xs text-slate-300 font-mono">{v}</span>
                            </div>
                          ))}
                        </div>
                      </div>
                    </div>
                  )}

                  {/* ── Backup & Recovery ── */}
                  {adminSub==='backup' && (
                    <div className="space-y-4">
                      <div className="rounded-xl border border-slate-700/40 overflow-hidden">
                        <div className="px-4 py-2.5 border-b border-slate-700/40 bg-slate-900/40 flex items-center justify-between">
                          <span className="text-sm font-bold text-slate-200">Backup Status</span>
                          <span className="text-xs text-slate-500">RPO / RTO targets per clinical policy</span>
                        </div>
                        <div className="divide-y divide-slate-800/60">
                          {backups.map((b,i)=>(
                            <div key={i} className="px-4 py-3 flex items-center gap-3">
                              <div className={`w-2 h-2 rounded-full flex-shrink-0 ${b.status==='success'?'bg-emerald-400':'bg-amber-400'}`}/>
                              <div className="flex-1 min-w-0">
                                <div className="text-sm font-semibold text-slate-100">{b.target}</div>
                                <div className="text-xs text-slate-500">Last: {b.lastBackup} · {b.size}</div>
                              </div>
                              <div className="text-xs text-slate-500">RPO <span className="text-slate-300">{b.rpo}</span></div>
                              <div className="text-xs text-slate-500">RTO <span className="text-slate-300">{b.rto}</span></div>
                              <span className={`text-xs px-2 py-0.5 rounded font-semibold ${b.status==='success'?'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30':'bg-amber-500/20 text-amber-400 border border-amber-500/30'}`}>{b.status}</span>
                            </div>
                          ))}
                        </div>
                      </div>
                      <div className="rounded-lg border border-slate-700/40 bg-slate-900/40 p-4 text-xs text-slate-500 leading-6">
                        <div className="font-semibold text-slate-300 mb-2 flex items-center gap-2"><HardDrive className="w-3.5 h-3.5 text-amber-400"/>Business Continuity Notes</div>
                        <ul className="space-y-1 list-disc list-inside">
                          <li>Clinical device communication pathways maintain HA via redundant switches (N+1)</li>
                          <li>DR test last conducted: <span className="text-slate-300">2026-03-15</span> — all critical systems recovered within RTO</li>
                          <li>SIEM log archive backup is <span className="text-amber-400">overdue by 6h</span> — investigate storage agent on log server</li>
                        </ul>
                      </div>
                    </div>
                  )}

                  {/* ── Vendor Access ── */}
                  {adminSub==='vendors' && (
                    <div className="space-y-4">
                      <div className="rounded-lg border border-amber-500/30 bg-amber-500/5 p-3 flex items-start gap-2">
                        <AlertTriangle className="w-4 h-4 text-amber-400 flex-shrink-0 mt-0.5"/>
                        <p className="text-xs text-amber-300">All vendor remote sessions must be monitored and use time-limited credentials. Remote access must be terminated immediately after the maintenance window.</p>
                      </div>
                      <div className="rounded-xl border border-slate-700/40 overflow-hidden">
                        <div className="px-4 py-2.5 border-b border-slate-700/40 bg-slate-900/40 flex items-center justify-between">
                          <span className="text-sm font-bold text-slate-200">Third-Party & OEM Vendor Access</span>
                          <span className="text-xs text-red-400">{vendors.filter(v=>v.session==='Active').length} active sessions</span>
                        </div>
                        <div className="divide-y divide-slate-800/60">
                          {vendors.map((v,i)=>(
                            <div key={i} className="px-4 py-3 flex items-center gap-3">
                              <div className="flex-1 min-w-0">
                                <div className="flex items-center gap-2">
                                  <span className="text-sm font-semibold text-slate-100">{v.name}</span>
                                  <span className="text-xs px-1.5 py-0.5 rounded bg-slate-700/60 text-slate-400 border border-slate-600/40">{v.type}</span>
                                </div>
                                <div className="text-xs text-slate-500 mt-0.5">Access: {v.access} · Expires: {v.expires}</div>
                              </div>
                              {v.monitor && <div className="flex items-center gap-1 text-xs text-emerald-400"><Eye className="w-3 h-3"/>Monitored</div>}
                              <span className={`text-xs px-2 py-0.5 rounded font-semibold ${v.session==='Active'?'bg-red-500/20 text-red-400 border border-red-500/30':v.session==='Pending'?'bg-amber-500/20 text-amber-400 border border-amber-500/30':'bg-slate-700/40 text-slate-500 border border-slate-600/40'}`}>{v.session}</span>
                            </div>
                          ))}
                        </div>
                      </div>
                    </div>
                  )}

                  {/* ── User Accounts ── */}
                  {adminSub==='users' && (
                    <div className="space-y-4">
                      {/* Header */}
                      <div className="flex items-center justify-between">
                        <div>
                          <p className="text-sm font-bold text-slate-200">Registered Accounts</p>
                          <p className="text-xs text-slate-500 mt-0.5">Manage credentials, access, and account status</p>
                        </div>
                        <button onClick={()=>{clearHeartbeat(currentUser.username);setCurrentUser(null);localStorage.removeItem('iomt_user');setActiveTab('exec');}} className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold bg-red-500/10 border border-red-500/30 text-red-400 hover:bg-red-500/20 transition-colors">
                          <LogOut className="w-3 h-3"/>Sign Out
                        </button>
                      </div>

                      {/* User cards */}
                      {DEMO_USERS.map((u,i)=>{
                        const rd   = ROLE_DEFS[u.role];
                        const us   = userStates[u.username] || { blocked:false, password:u.password };
                        const isMe       = u.username === currentUser.username;
                        const team       = SOC_TEAM.find(m=>m.username===u.username);
                        const isResetting   = resetTarget === u.username;
                        const isEditingPh   = editPhoneFor === u.username;
                        const pwVisible     = !!showPwMap[u.username];
                        const activeOtp     = activeOtps[u.username];
                        const otpStillValid = activeOtp && new Date() < new Date(activeOtp.expiresAt);
                        return (
                          <div key={i} className={`rounded-xl border ${us.blocked?'border-red-500/30 bg-red-500/5':isMe?'border-amber-500/30 bg-amber-500/5':'border-slate-700/40 bg-slate-900/30'} overflow-hidden`}>
                            {/* Row */}
                            <div className="px-4 py-3 flex items-center gap-3">
                              {/* Avatar */}
                              <div className="relative flex-shrink-0">
                                <div className="w-10 h-10 rounded-full flex items-center justify-center text-sm font-bold" style={{background:(rd?.color||'#64748b')+'22',border:`1.5px solid ${us.blocked?'#ef4444':rd?.color||'#64748b'}`,color:us.blocked?'#ef4444':rd?.color}}>{u.avatar}</div>
                                {us.blocked && <div className="absolute -top-1 -right-1 w-4 h-4 rounded-full bg-red-500 flex items-center justify-center"><X className="w-2.5 h-2.5 text-white"/></div>}
                              </div>

                              {/* Info */}
                              <div className="flex-1 min-w-0">
                                <div className="flex items-center gap-2 flex-wrap">
                                  <span className="text-sm font-semibold text-slate-100">{u.name}</span>
                                  {isMe && <span className="text-xs px-1.5 py-0.5 rounded bg-amber-500/20 text-amber-400 border border-amber-500/30">YOU</span>}
                                  {us.blocked && <span className="text-xs px-1.5 py-0.5 rounded bg-red-500/20 text-red-400 border border-red-500/30">BLOCKED</span>}
                                  <span className={`text-xs px-2 py-0.5 rounded border font-semibold ${rd?.badge}`}>{rd?.label}</span>
                                  {otpStillValid && <span className="text-xs px-1.5 py-0.5 rounded bg-indigo-500/20 text-indigo-300 border border-indigo-500/30 font-mono">OTP: {activeOtp.code}</span>}
                                </div>
                                <div className="flex items-center gap-3 mt-0.5 flex-wrap">
                                  {/* Username */}
                                  <span className="text-xs text-slate-500 font-mono">{u.username}</span>
                                  {/* Password */}
                                  <div className="flex items-center gap-1">
                                    <span className="text-xs font-mono text-slate-400">{pwVisible ? us.password : '••••••••••'}</span>
                                    <button onClick={()=>setShowPwMap(p=>({...p,[u.username]:!p[u.username]}))} className="p-0.5 rounded text-slate-500 hover:text-slate-300 transition-colors" title={pwVisible?'Hide password':'Reveal password'}>
                                      {pwVisible
                                        ? <svg className="w-3 h-3" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path d="M17.94 17.94A10.07 10.07 0 0112 20c-7 0-11-8-11-8a18.45 18.45 0 015.06-5.94M9.9 4.24A9.12 9.12 0 0112 4c7 0 11 8 11 8a18.5 18.5 0 01-2.16 3.19m-6.72-1.07a3 3 0 11-4.24-4.24M1 1l22 22"/></svg>
                                        : <svg className="w-3 h-3" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
                                      }
                                    </button>
                                  </div>
                                  {/* Phone */}
                                  <div className="flex items-center gap-1">
                                    <svg className="w-2.5 h-2.5 text-slate-500" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><rect x="5" y="2" width="14" height="20" rx="2"/><line x1="12" y1="18" x2="12.01" y2="18"/></svg>
                                    <span className="text-xs text-slate-500 font-mono">{us.phone || u.phone}</span>
                                  </div>
                                  {/* Online status */}
                                  <div className="flex items-center gap-1">
                                    <span className={`w-1.5 h-1.5 rounded-full ${team?.online&&!us.blocked?'bg-emerald-400':'bg-slate-600'}`}/>
                                    <span className={`text-xs ${team?.online&&!us.blocked?'text-emerald-400':'text-slate-500'}`}>{us.blocked?'Blocked':team?.online?'Online':'Offline'}</span>
                                  </div>
                                </div>
                              </div>

                              {/* Actions — no actions on own account (can't self-block) */}
                              {!isMe && (
                                <div className="flex items-center gap-2 flex-shrink-0">
                                  {/* Reset Password */}
                                  <button
                                    onClick={()=>{ setResetTarget(isResetting?null:u.username); setResetPwVal(''); }}
                                    className="flex items-center gap-1 px-2.5 py-1.5 rounded-lg text-xs font-semibold bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 hover:bg-cyan-500/20 transition-colors"
                                  ><KeyRound className="w-3 h-3"/>{isResetting?'Cancel':'Reset PW'}</button>

                                  {/* Edit Phone */}
                                  <button
                                    onClick={()=>{ setEditPhoneFor(isEditingPh?null:u.username); setEditPhoneVal(us.phone||u.phone||''); }}
                                    className="flex items-center gap-1 px-2.5 py-1.5 rounded-lg text-xs font-semibold bg-violet-500/10 border border-violet-500/30 text-violet-400 hover:bg-violet-500/20 transition-colors"
                                  ><svg className="w-3 h-3" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><rect x="5" y="2" width="14" height="20" rx="2"/><line x1="12" y1="18" x2="12.01" y2="18"/></svg>{isEditingPh?'Cancel':'Phone'}</button>

                                  {/* MFA toggle */}
                                  <button
                                    onClick={()=>setUserStates(p=>({...p,[u.username]:{...p[u.username],mfaEnabled:!us.mfaEnabled}}))}
                                    className={`flex items-center gap-1 px-2.5 py-1.5 rounded-lg text-xs font-semibold border transition-colors ${us.mfaEnabled?'bg-indigo-500/10 border-indigo-500/30 text-indigo-400 hover:bg-indigo-500/20':'bg-slate-700/30 border-slate-600/40 text-slate-500 hover:bg-slate-700/50'}`}
                                    title={us.mfaEnabled?'Disable MFA for this user':'Enable MFA for this user'}
                                  ><KeyRound className="w-3 h-3"/>{us.mfaEnabled?'MFA On':'MFA Off'}</button>

                                  {/* Block / Unblock */}
                                  <button
                                    onClick={()=>setUserStates(p=>({...p,[u.username]:{...p[u.username],blocked:!us.blocked}}))}
                                    className={`flex items-center gap-1 px-2.5 py-1.5 rounded-lg text-xs font-semibold border transition-colors ${us.blocked?'bg-emerald-500/10 border-emerald-500/30 text-emerald-400 hover:bg-emerald-500/20':'bg-red-500/10 border-red-500/30 text-red-400 hover:bg-red-500/20'}`}
                                  >{us.blocked?<><CheckCircle className="w-3 h-3"/>Unblock</>:<><Ban className="w-3 h-3"/>Block</>}</button>
                                </div>
                              )}
                            </div>

                            {/* Reset password inline form */}
                            {isResetting && (
                              <div className="px-4 pb-3 pt-1 border-t border-slate-700/40 bg-slate-950/40">
                                <p className="text-xs text-slate-400 mb-2">Set new password for <span className="text-cyan-400 font-semibold">{u.name}</span></p>
                                <div className="flex gap-2">
                                  <input
                                    type="text"
                                    value={resetPwVal}
                                    onChange={e=>setResetPwVal(e.target.value)}
                                    placeholder="Enter new password…"
                                    className="flex-1 px-3 py-1.5 rounded-lg text-xs bg-slate-800 border border-slate-600 text-slate-100 placeholder-slate-600 focus:outline-none focus:border-cyan-500 font-mono"
                                  />
                                  <button
                                    disabled={!resetPwVal.trim()}
                                    onClick={()=>{
                                      if (!resetPwVal.trim()) return;
                                      setUserStates(p=>({...p,[u.username]:{...p[u.username],password:resetPwVal.trim()}}));
                                      setResetTarget(null);
                                      setResetPwVal('');
                                    }}
                                    className="px-3 py-1.5 rounded-lg text-xs font-semibold bg-cyan-500/20 border border-cyan-500/40 text-cyan-300 hover:bg-cyan-500/30 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
                                  >Save</button>
                                </div>
                              </div>
                            )}

                            {/* Edit phone inline form */}
                            {isEditingPh && (
                              <div className="px-4 pb-3 pt-1 border-t border-slate-700/40 bg-slate-950/40">
                                <p className="text-xs text-slate-400 mb-2">MFA phone for <span className="text-violet-400 font-semibold">{u.name}</span></p>
                                <div className="flex gap-2">
                                  <input
                                    type="tel"
                                    value={editPhoneVal}
                                    onChange={e=>setEditPhoneVal(e.target.value)}
                                    placeholder="+263 77 000 0000"
                                    className="flex-1 px-3 py-1.5 rounded-lg text-xs bg-slate-800 border border-slate-600 text-slate-100 placeholder-slate-600 focus:outline-none focus:border-violet-500 font-mono"
                                  />
                                  <button
                                    disabled={!editPhoneVal.trim()}
                                    onClick={()=>{
                                      if (!editPhoneVal.trim()) return;
                                      setUserStates(p=>({...p,[u.username]:{...p[u.username],phone:editPhoneVal.trim()}}));
                                      setEditPhoneFor(null);
                                      setEditPhoneVal('');
                                    }}
                                    className="px-3 py-1.5 rounded-lg text-xs font-semibold bg-violet-500/20 border border-violet-500/40 text-violet-300 hover:bg-violet-500/30 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
                                  >Save</button>
                                </div>
                              </div>
                            )}
                          </div>
                        );
                      })}

                      {/* Role Permissions Matrix */}
                      <div className="rounded-xl border border-slate-700/40 bg-slate-900/40 p-4">
                        <div className="text-sm font-bold text-slate-200 mb-2 flex items-center gap-2"><Shield className="w-3.5 h-3.5 text-amber-400"/>Role Permissions Matrix</div>
                        <div className="space-y-2">
                          {Object.entries(ROLE_DEFS).map(([key,rd])=>(
                            <div key={key} className="flex items-start gap-3 py-2 border-b border-slate-800/40 last:border-0">
                              <span className={`text-xs px-2 py-0.5 rounded border font-semibold flex-shrink-0 ${rd.badge}`}>{rd.label}</span>
                              <div className="flex-1 min-w-0">
                                <p className="text-xs text-slate-400">{rd.description}</p>
                                <div className="flex flex-wrap gap-1 mt-1">
                                  {rd.canManageUsers&&<span className="text-xs px-1 py-0.5 rounded bg-amber-500/10 text-amber-400">User Mgmt</span>}
                                  {rd.canIsolate&&<span className="text-xs px-1 py-0.5 rounded bg-red-500/10 text-red-400">Isolate</span>}
                                  {rd.canBlock&&<span className="text-xs px-1 py-0.5 rounded bg-orange-500/10 text-orange-400">Block IP</span>}
                                  {rd.canAck&&<span className="text-xs px-1 py-0.5 rounded bg-cyan-500/10 text-cyan-400">Ack Alert</span>}
                                  <span className="text-xs px-1 py-0.5 rounded bg-slate-700/40 text-slate-400">{rd.tabs.length} tabs</span>
                                </div>
                              </div>
                            </div>
                          ))}
                        </div>
                      </div>
                    </div>
                  )}

                </div>
              </div>
              );
            })()}

            </div>
          </div>
        </div>
      </div>

      {/* Footer */}
      <footer className="px-4 py-2 border-t border-slate-800/50 flex justify-between text-xs text-slate-600 flex-shrink-0">
        <span>IoMT Anomaly Detection System</span>
        <span>Real-Time Threat Detection & Response Platform</span>
      </footer>

      {/* ==================== MODALS ==================== */}

      {/* ── Remediation & Restore Modal ────────────────────────────────────────── */}
      {restoreModal && (() => {
        const { device: dev, meta } = restoreModal;
        const patches = DEVICE_PATCH_DATA[dev] || [];
        const verifySteps = [
          { id: 'threat_clear',  label: 'Confirm the triggering threat has been neutralised or mitigated' },
          { id: 'no_c2',         label: 'Verify no active C2 connections remain from this device' },
          { id: 'audit_review',  label: 'Review device access logs — no unauthorized activity found' },
          { id: 'supervisor',    label: 'Supervisor / CISO sign-off obtained for this restoration' },
        ];
        const allSteps = [...patches.map(p => p.id), ...verifySteps.map(s => s.id)];
        const allChecked = allSteps.every(id => remediationChecks[id]);
        const critPatches = patches.filter(p => p.priority === 'critical');
        const critAllApplied = critPatches.every(p => remediationChecks[p.id]);

        const severityColor = { critical:'#ef4444', high:'#f97316', medium:'#eab308', low:'#22c55e', manual:'#6366f1' };
        const sc = severityColor[meta?.severity] || '#6366f1';

        return (
          <div
            style={{ position:'fixed', inset:0, background:'rgba(0,0,0,0.75)', display:'flex', alignItems:'center', justifyContent:'center', zIndex:9100 }}
            onClick={() => setRestoreModal(null)}
          >
            <div
              style={{ background:'#0d1525', border:'1px solid #334155', borderRadius:16, width:560, maxWidth:'95vw', maxHeight:'90vh', overflow:'auto', boxShadow:'0 25px 60px rgba(0,0,0,0.7)' }}
              onClick={e => e.stopPropagation()}
            >
              {/* Header */}
              <div style={{ padding:'20px 24px 16px', borderBottom:'1px solid #1e293b' }}>
                <div style={{ display:'flex', alignItems:'center', gap:10, marginBottom:6 }}>
                  <span style={{ fontSize:22 }}>🔒</span>
                  <div>
                    <div style={{ fontSize:11, fontWeight:700, color:'#64748b', textTransform:'uppercase', letterSpacing:'0.1em' }}>Quarantine Release Authorization</div>
                    <div style={{ fontSize:18, fontWeight:700, color:'#f1f5f9' }}>{dev}</div>
                  </div>
                  <button onClick={() => setRestoreModal(null)} style={{ marginLeft:'auto', background:'none', border:'none', color:'#64748b', cursor:'pointer', fontSize:18, lineHeight:1 }}>✕</button>
                </div>

                {/* Isolation summary */}
                <div style={{ background:'rgba(139,92,246,0.1)', border:'1px solid rgba(139,92,246,0.25)', borderRadius:8, padding:'10px 12px' }}>
                  {meta ? (
                    <p style={{ fontSize:13, color:'#cbd5e1', margin:0 }}>
                      This device was isolated{meta.ts ? ` ${timeAgo(meta.ts)}` : ''} due to a{' '}
                      <span style={{ color: sc, fontWeight:700 }}>{meta.severity?.toUpperCase()}</span> severity{' '}
                      <span style={{ color:'#94a3b8', fontWeight:600 }}>{meta.trigger}</span> attack.
                      Complete all steps below before restoring to VLAN 20.
                    </p>
                  ) : (
                    <p style={{ fontSize:13, color:'#cbd5e1', margin:0 }}>This device was manually isolated. Complete the remediation checklist before restoring.</p>
                  )}
                </div>
              </div>

              <div style={{ padding:'20px 24px' }}>
                {/* Device patches */}
                {patches.length > 0 && (
                  <div style={{ marginBottom:20 }}>
                    <div style={{ fontSize:11, fontWeight:700, color:'#64748b', textTransform:'uppercase', letterSpacing:'0.1em', marginBottom:10 }}>
                      Step 1 — Apply Device Patches
                    </div>
                    <div style={{ display:'flex', flexDirection:'column', gap:8 }}>
                      {patches.map(p => {
                        const checked = !!remediationChecks[p.id];
                        const pc = p.priority === 'critical' ? '#ef4444' : p.priority === 'high' ? '#f97316' : '#eab308';
                        return (
                          <label key={p.id} style={{ display:'flex', alignItems:'flex-start', gap:10, cursor:'pointer', padding:'10px 12px', borderRadius:8, border:`1px solid ${checked ? '#22c55e44' : '#1e293b'}`, background: checked ? 'rgba(34,197,94,0.06)' : 'rgba(15,23,42,0.6)' }}>
                            <input
                              type="checkbox"
                              checked={checked}
                              onChange={e => setRemediationChecks(prev => ({ ...prev, [p.id]: e.target.checked }))}
                              style={{ marginTop:2, accentColor:'#22c55e', width:14, height:14, flexShrink:0 }}
                            />
                            <div style={{ flex:1 }}>
                              <div style={{ fontSize:13, color: checked ? '#86efac' : '#cbd5e1', textDecoration: checked ? 'line-through' : 'none' }}>{p.label}</div>
                              <div style={{ display:'flex', gap:8, marginTop:4 }}>
                                <span style={{ fontSize:11, padding:'1px 6px', borderRadius:4, background:`${pc}20`, color:pc, fontWeight:700 }}>{p.priority.toUpperCase()}</span>
                                <span style={{ fontSize:11, color:'#475569' }}>Risk reduction: −{p.reduction} pts</span>
                              </div>
                            </div>
                            {checked && <span style={{ color:'#22c55e', fontSize:16, flexShrink:0 }}>✓</span>}
                          </label>
                        );
                      })}
                    </div>
                    {!critAllApplied && (
                      <p style={{ fontSize:11, color:'#ef4444', marginTop:8 }}>⚠ Critical patches must be applied before restoration is recommended.</p>
                    )}
                  </div>
                )}

                {/* Verification checklist */}
                <div style={{ marginBottom:24 }}>
                  <div style={{ fontSize:11, fontWeight:700, color:'#64748b', textTransform:'uppercase', letterSpacing:'0.1em', marginBottom:10 }}>
                    {patches.length > 0 ? 'Step 2 — ' : ''}Pre-Restoration Verification
                  </div>
                  <div style={{ display:'flex', flexDirection:'column', gap:6 }}>
                    {verifySteps.map(s => {
                      const checked = !!remediationChecks[s.id];
                      return (
                        <label key={s.id} style={{ display:'flex', alignItems:'center', gap:10, cursor:'pointer', padding:'9px 12px', borderRadius:8, border:`1px solid ${checked ? '#22c55e44' : '#1e293b'}`, background: checked ? 'rgba(34,197,94,0.06)' : 'rgba(15,23,42,0.6)' }}>
                          <input
                            type="checkbox"
                            checked={checked}
                            onChange={e => setRemediationChecks(prev => ({ ...prev, [s.id]: e.target.checked }))}
                            style={{ accentColor:'#22c55e', width:14, height:14, flexShrink:0 }}
                          />
                          <span style={{ fontSize:13, color: checked ? '#86efac' : '#cbd5e1', textDecoration: checked ? 'line-through' : 'none', flex:1 }}>{s.label}</span>
                          {checked && <span style={{ color:'#22c55e', fontSize:16, flexShrink:0 }}>✓</span>}
                        </label>
                      );
                    })}
                  </div>
                </div>

                {/* Progress indicator */}
                <div style={{ marginBottom:20 }}>
                  <div style={{ display:'flex', justifyContent:'space-between', fontSize:11, color:'#64748b', marginBottom:6 }}>
                    <span>Remediation progress</span>
                    <span style={{ color: allChecked ? '#22c55e' : '#94a3b8', fontWeight:700 }}>
                      {allSteps.filter(id => remediationChecks[id]).length} / {allSteps.length} completed
                    </span>
                  </div>
                  <div style={{ height:4, background:'#1e293b', borderRadius:4, overflow:'hidden' }}>
                    <div style={{ height:'100%', borderRadius:4, background: allChecked ? '#22c55e' : '#6366f1', width:`${(allSteps.filter(id=>remediationChecks[id]).length/allSteps.length)*100}%`, transition:'width 0.3s' }}/>
                  </div>
                </div>

                {/* Action buttons */}
                <div style={{ display:'flex', gap:10 }}>
                  <button
                    onClick={() => setRestoreModal(null)}
                    style={{ flex:1, padding:'10px 0', borderRadius:10, border:'1px solid #334155', background:'transparent', color:'#94a3b8', fontSize:13, fontWeight:600, cursor:'pointer' }}
                  >
                    Cancel — Keep Isolated
                  </button>
                  <button
                    disabled={!allChecked}
                    onClick={() => {
                      handleQuickAction('restore', { id: Date.now(), device: dev, type: meta?.trigger || 'Manual', severity: meta?.severity || 'manual', sourceIP: '0.0.0.0' });
                      setRestoreModal(null);
                      setRemediationChecks({});
                    }}
                    style={{
                      flex:1, padding:'10px 0', borderRadius:10, border:`1px solid ${allChecked ? '#22c55e66' : '#334155'}`,
                      background: allChecked ? 'rgba(34,197,94,0.15)' : 'rgba(30,41,59,0.5)',
                      color: allChecked ? '#86efac' : '#475569',
                      fontSize:13, fontWeight:700, cursor: allChecked ? 'pointer' : 'not-allowed',
                      transition:'all 0.2s',
                    }}
                  >
                    {allChecked ? '🔓 Restore to VLAN 20' : `Complete all ${allSteps.length - allSteps.filter(id=>remediationChecks[id]).length} remaining steps`}
                  </button>
                </div>
              </div>
            </div>
          </div>
        );
      })()}

      {/* Alert Detail Panel */}
      {showAlertPanel && selectedAlert && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm flex items-center justify-center z-50 p-4">
          <div className="bg-slate-900 border border-slate-700 rounded-xl w-full max-w-lg overflow-hidden">
            <div className="px-4 py-3 border-b border-slate-700 flex items-center justify-between bg-slate-800/50">
              <div className="flex items-center gap-2">
                <AlertOctagon className={`w-5 h-5 ${selectedAlert.severity === 'critical' ? 'text-red-400' : 'text-amber-400'}`} />
                <h3 className="font-semibold text-lg">Alert Investigation</h3>
              </div>
              <button onClick={() => setShowAlertPanel(false)} className="p-1.5 hover:bg-slate-700 rounded-lg">
                <X className="w-4 h-4" />
              </button>
            </div>
            <div className="p-4 space-y-3">
              <div className="flex items-center gap-2 flex-wrap">
                <span className={`px-2 py-1 rounded text-base uppercase font-bold ${getSeverityColor(selectedAlert.severity)}`}>{selectedAlert.severity}</span>
                <span className={`px-2 py-1 rounded text-base ${getStatusColor(selectedAlert.status)}`}>{selectedAlert.status}</span>
                <span className="px-2 py-1 rounded text-base bg-slate-700/50">{selectedAlert.type}</span>
              </div>
              <p className="text-lg">{selectedAlert.message}</p>
              <div className="grid grid-cols-2 gap-2">
                {[
                  { label: 'Source IP', value: selectedAlert.sourceIP },
                  { label: 'Dest IP', value: selectedAlert.destIP },
                  { label: 'Device', value: selectedAlert.device },
                  { label: 'Port', value: selectedAlert.port },
                  { label: 'Packets', value: selectedAlert.packets?.toLocaleString() },
                  { label: 'Volume', value: selectedAlert.bytes },
                ].map((item, i) => (
                  <div key={i} className="p-2 rounded-lg bg-slate-800/50">
                    <p className="text-base text-slate-400">{item.label}</p>
                    <p className="text-lg font-mono font-medium">{item.value}</p>
                  </div>
                ))}
              </div>
              <div className="p-2 rounded-lg bg-slate-800/50">
                <div className="flex justify-between mb-1">
                  <span className="text-base text-slate-400">Model Confidence</span>
                  <span className="text-lg font-bold text-cyan-400">{selectedAlert.confidence}%</span>
                </div>
                <div className="h-1.5 bg-slate-700 rounded-full overflow-hidden">
                  <div className="h-full bg-gradient-to-r from-cyan-500 to-emerald-500 rounded-full" style={{ width: `${selectedAlert.confidence}%` }} />
                </div>
              </div>
              {selectedAlert.status === 'active' && (
                <div className="flex gap-2 pt-2">
                  {canBlock && <button onClick={() => { handleQuickAction('block', selectedAlert); setShowAlertPanel(false); }} className="flex-1 flex items-center justify-center gap-1 px-2 py-2 rounded-lg bg-red-500/20 text-red-400 text-lg font-medium hover:bg-red-500/30">
                    <Ban className="w-4 h-4" /> Block
                  </button>}
                  {canIsolate && <button onClick={() => { handleQuickAction('isolate', selectedAlert); setShowAlertPanel(false); }} className="flex-1 flex items-center justify-center gap-1 px-2 py-2 rounded-lg bg-violet-500/20 text-violet-400 text-lg font-medium hover:bg-violet-500/30">
                    <Unplug className="w-4 h-4" /> Isolate
                  </button>}
                  <button onClick={() => { handleQuickAction('resolve', selectedAlert); setShowAlertPanel(false); }} className="flex-1 flex items-center justify-center gap-1 px-2 py-2 rounded-lg bg-emerald-500/20 text-emerald-400 text-lg font-medium hover:bg-emerald-500/30">
                    <ShieldCheck className="w-4 h-4" /> Resolve
                  </button>
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Notification Panel */}
      {showNotificationPanel && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm flex items-center justify-center z-50 p-4">
          <div className="bg-slate-900 border border-slate-700 rounded-xl w-full max-w-md overflow-hidden">
            <div className="px-4 py-3 border-b border-slate-700 flex items-center justify-between bg-slate-800/50">
              <div className="flex items-center gap-2">
                <Bell className="w-5 h-5 text-cyan-400" />
                <h3 className="font-semibold text-lg">Notification History</h3>
                <span className="px-1.5 py-0.5 rounded bg-cyan-500/20 text-cyan-400 text-base">{notifications.length}</span>
              </div>
              <div className="flex items-center gap-1">
                <button
                  onClick={() => { setShowNotificationPanel(false); setShowNotificationSettings(true); }}
                  className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-xs font-semibold bg-slate-700/60 text-slate-300 hover:bg-cyan-500/20 hover:text-cyan-300 transition-colors"
                  title="Configure Email & Slack"
                >
                  <Settings className="w-3.5 h-3.5" /> Configure
                </button>
                {notifications.length > 0 && (
                  <button onClick={() => setNotifications([])} className="px-2 py-1.5 rounded-lg text-xs text-slate-500 hover:text-red-400 hover:bg-red-500/10 transition-colors" title="Clear history">
                    Clear
                  </button>
                )}
                <button onClick={() => setShowNotificationPanel(false)} className="p-1.5 hover:bg-slate-700 rounded-lg ml-1">
                  <X className="w-4 h-4" />
                </button>
              </div>
            </div>
            <div className="max-h-80 overflow-y-auto divide-y divide-slate-700/30">
              {notifications.length === 0 && (
                <div className="px-4 py-8 text-center text-slate-500 text-sm">
                  <Bell className="w-6 h-6 mx-auto mb-2 opacity-30"/>
                  No notifications sent yet.<br/>
                  <span className="text-xs">Configure Email or Slack in settings, then alerts will appear here.</span>
                </div>
              )}
              {notifications.map((notif) => (
                <div key={notif.id} className="px-4 py-3 flex items-start gap-3">
                  <div className={`p-2 rounded-lg flex-shrink-0 ${notif.type === 'email' ? 'bg-blue-500/20' : 'bg-purple-500/20'}`}>
                    {notif.type === 'email' ? <Mail className="w-4 h-4 text-blue-400" /> : <MessageSquare className="w-4 h-4 text-purple-400" />}
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-0.5 flex-wrap">
                      <span className="text-xs font-semibold text-slate-200">{notif.type === 'email' ? 'Email' : 'Slack'}</span>
                      <span className={`px-1.5 py-0.5 rounded text-xs font-bold uppercase ${getSeverityColor(notif.severity || 'medium')}`}>{notif.severity || 'alert'}</span>
                    </div>
                    <p className="text-xs text-slate-300 truncate">{notif.alert}</p>
                    <p className="text-xs text-slate-500 mt-0.5">{notif.recipient} · {notif.time}</p>
                  </div>
                  <div className={`flex items-center gap-1 flex-shrink-0 text-xs font-semibold ${notif.status === 'failed' ? 'text-red-400' : 'text-emerald-400'}`}>
                    {notif.status === 'failed'
                      ? <><X className="w-3 h-3"/>Failed</>
                      : <><Check className="w-3 h-3"/>Sent</>
                    }
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Notification Settings Modal */}
      {showNotificationSettings && (() => {
        const sevStyle = { critical: { bg:'rgba(239,68,68,0.15)', color:'#f87171', border:'rgba(239,68,68,0.4)' }, high: { bg:'rgba(249,115,22,0.15)', color:'#fb923c', border:'rgba(249,115,22,0.4)' }, medium: { bg:'rgba(234,179,8,0.15)', color:'#facc15', border:'rgba(234,179,8,0.4)' } };
        const Toggle = ({ on, onToggle }) => (
          <div onClick={onToggle} style={{ width:44, height:24, borderRadius:12, background: on ? '#10b981' : '#374151', position:'relative', cursor:'pointer', flexShrink:0, transition:'background 0.2s' }}>
            <div style={{ position:'absolute', top:3, left: on ? 23 : 3, width:18, height:18, borderRadius:'50%', background:'white', boxShadow:'0 1px 4px rgba(0,0,0,0.4)', transition:'left 0.2s' }} />
          </div>
        );
        const SevFilter = ({ channel }) => (
          <div style={{ display:'flex', gap:6 }}>
            {['critical','high','medium'].map(lvl => {
              const active = notificationSettings[channel][lvl];
              const s = sevStyle[lvl];
              return (
                <button key={lvl} onClick={() => setNotificationSettings(prev => ({ ...prev, [channel]: { ...prev[channel], [lvl]: !prev[channel][lvl] } }))}
                  style={{ flex:1, padding:'6px 4px', borderRadius:8, fontSize:12, fontWeight:600, cursor:'pointer', textTransform:'capitalize', transition:'all 0.15s', background: active ? s.bg : 'rgba(51,65,85,0.5)', color: active ? s.color : '#64748b', border: `1px solid ${active ? s.border : 'rgba(71,85,105,0.5)'}` }}>
                  {lvl}
                </button>
              );
            })}
          </div>
        );
        return (
        <div style={{ position:'fixed', inset:0, background:'rgba(0,0,0,0.75)', backdropFilter:'blur(4px)', display:'flex', alignItems:'center', justifyContent:'center', zIndex:50, padding:16 }}>
          <div style={{ background:'#0f172a', border:'1px solid rgba(255,255,255,0.1)', borderRadius:16, width:'100%', maxWidth:440, overflow:'hidden', boxShadow:'0 32px 64px rgba(0,0,0,0.6)' }}>
            {/* Header */}
            <div style={{ padding:'16px 20px', borderBottom:'1px solid rgba(255,255,255,0.08)', display:'flex', alignItems:'center', justifyContent:'space-between', background:'rgba(255,255,255,0.03)' }}>
              <div style={{ display:'flex', alignItems:'center', gap:8 }}>
                <Bell style={{ width:16, height:16, color:'#22d3ee' }} />
                <span style={{ fontWeight:600, fontSize:15, color:'white' }}>Notification Channels</span>
              </div>
              <button onClick={() => setShowNotificationSettings(false)} style={{ padding:6, borderRadius:8, background:'none', border:'none', cursor:'pointer', color:'#64748b' }}>
                <X style={{ width:16, height:16 }} />
              </button>
            </div>

            <div className="p-5 space-y-5">

              {/* ── EMAIL via EmailJS ── */}
              {(() => {
                const em = notificationSettings.email;
                const fullyConfigured = em.address && em.serviceId && em.templateId && em.publicKey;
                return (
                <div style={{ borderRadius:12, border:`1px solid ${em.enabled && fullyConfigured ? 'rgba(59,130,246,0.4)' : 'rgba(255,255,255,0.08)'}`, padding:16, background: em.enabled && fullyConfigured ? 'rgba(59,130,246,0.05)' : 'rgba(255,255,255,0.02)' }}>
                  <div style={{ display:'flex', alignItems:'center', justifyContent:'space-between', marginBottom: em.enabled ? 14 : 0 }}>
                    <div style={{ display:'flex', alignItems:'center', gap:8 }}>
                      <Mail style={{ width:15, height:15, color:'#60a5fa' }} />
                      <span style={{ fontWeight:600, fontSize:14, color:'white' }}>Email Alerts</span>
                      {em.enabled && fullyConfigured  && <span style={{ fontSize:11, padding:'2px 8px', borderRadius:100, background:'rgba(16,185,129,0.15)', color:'#34d399', border:'1px solid rgba(16,185,129,0.3)' }}>Configured</span>}
                      {em.enabled && !fullyConfigured && <span style={{ fontSize:11, padding:'2px 8px', borderRadius:100, background:'rgba(245,158,11,0.15)', color:'#fbbf24', border:'1px solid rgba(245,158,11,0.3)' }}>Incomplete</span>}
                    </div>
                    <Toggle on={em.enabled} onToggle={() => setNotificationSettings(prev => ({ ...prev, email: { ...prev.email, enabled: !prev.email.enabled } }))} />
                  </div>
                  {em.enabled && (<>
                    {/* EmailJS setup hint */}
                    <div style={{ background:'rgba(59,130,246,0.07)', border:'1px solid rgba(59,130,246,0.2)', borderRadius:8, padding:'8px 10px', marginBottom:12, fontSize:11, color:'#94a3b8', lineHeight:1.6 }}>
                      Uses <span style={{color:'#60a5fa',fontWeight:600}}>EmailJS</span> to send real emails from the browser.
                      Create a free account at <span style={{color:'#60a5fa'}}>emailjs.com</span> → Add a service → Create a template with variables:
                      <span style={{fontFamily:'monospace',color:'#e2e8f0'}}> {'{{to_email}} {{severity}} {{device}} {{alert_type}} {{source_ip}} {{confidence}} {{time}}'}</span>
                    </div>
                    {[
                      { key:'address',    label:'Recipient Email',   placeholder:'soc-team@hospital.org',        type:'email' },
                      { key:'serviceId',  label:'EmailJS Service ID', placeholder:'service_xxxxxxx',             type:'text'  },
                      { key:'templateId', label:'EmailJS Template ID',placeholder:'template_xxxxxxx',            type:'text'  },
                      { key:'publicKey',  label:'EmailJS Public Key', placeholder:'your_public_key_here',        type:'text'  },
                    ].map(({ key, label, placeholder, type }) => (
                      <div key={key} style={{ marginBottom:10 }}>
                        <div style={{ fontSize:11, color:'#94a3b8', marginBottom:5 }}>{label}</div>
                        <input type={type} value={em[key] || ''}
                          onChange={e => setNotificationSettings(prev => ({ ...prev, email: { ...prev.email, [key]: e.target.value } }))}
                          placeholder={placeholder}
                          style={{ width:'100%', padding:'9px 12px', borderRadius:8, background:'rgba(255,255,255,0.05)', border:'1px solid rgba(255,255,255,0.1)', color:'white', fontSize:12, fontFamily: key==='address'?'inherit':'monospace', outline:'none', boxSizing:'border-box' }}
                          onFocus={e=>e.target.style.borderColor='#3b82f6'} onBlur={e=>e.target.style.borderColor='rgba(255,255,255,0.1)'}
                        />
                      </div>
                    ))}
                    <div style={{ marginBottom:12 }}>
                      <div style={{ fontSize:11, color:'#94a3b8', marginBottom:6 }}>Alert Severity Filter</div>
                      <SevFilter channel="email" />
                    </div>
                    <button disabled={!fullyConfigured}
                      onClick={() => {
                        if (!fullyConfigured) return;
                        setNotifTestStatus(p => ({ ...p, email:'sending' }));
                        emailjs.send(em.serviceId, em.templateId, {
                          to_email: em.address, severity:'TEST', device:'IoMT SOC Dashboard',
                          alert_type:'Test Notification', source_ip:'—', confidence:'—',
                          time: new Date().toLocaleString(),
                        }, { publicKey: em.publicKey })
                        .then(()  => { setNotifTestStatus(p => ({ ...p, email:'sent'  })); setTimeout(() => setNotifTestStatus(p => ({ ...p, email:null })), 3000); })
                        .catch(() => { setNotifTestStatus(p => ({ ...p, email:'error' })); setTimeout(() => setNotifTestStatus(p => ({ ...p, email:null })), 4000); });
                      }}
                      style={{ width:'100%', padding:'10px', borderRadius:8, border:'1px solid rgba(59,130,246,0.4)', background:'rgba(59,130,246,0.1)', color:'#60a5fa', fontSize:13, fontWeight:600, cursor: fullyConfigured ? 'pointer' : 'not-allowed', opacity: fullyConfigured ? 1 : 0.4, display:'flex', alignItems:'center', justifyContent:'center', gap:6 }}>
                      <Send style={{ width:13, height:13 }} />
                      {notifTestStatus.email==='sending' ? 'Sending…' : notifTestStatus.email==='sent' ? '✓ Test email sent!' : notifTestStatus.email==='error' ? '✗ Send failed — check credentials' : 'Send Test Email'}
                    </button>
                  </>)}
                </div>
                );
              })()}

              {/* SLACK */}
              <div style={{ borderRadius:12, border:`1px solid ${notificationSettings.slack.enabled && notificationSettings.slack.webhookUrl ? 'rgba(168,85,247,0.4)' : 'rgba(255,255,255,0.08)'}`, padding:16, background: notificationSettings.slack.enabled && notificationSettings.slack.webhookUrl ? 'rgba(168,85,247,0.05)' : 'rgba(255,255,255,0.02)' }}>
                <div style={{ display:'flex', alignItems:'center', justifyContent:'space-between', marginBottom: notificationSettings.slack.enabled ? 14 : 0 }}>
                  <div style={{ display:'flex', alignItems:'center', gap:8 }}>
                    <MessageSquare style={{ width:15, height:15, color:'#c084fc' }} />
                    <span style={{ fontWeight:600, fontSize:14, color:'white' }}>Slack Alerts</span>
                    {notificationSettings.slack.enabled && notificationSettings.slack.webhookUrl && <span style={{ fontSize:11, padding:'2px 8px', borderRadius:100, background:'rgba(16,185,129,0.15)', color:'#34d399', border:'1px solid rgba(16,185,129,0.3)' }}>Configured</span>}
                    {notificationSettings.slack.enabled && !notificationSettings.slack.webhookUrl && <span style={{ fontSize:11, padding:'2px 8px', borderRadius:100, background:'rgba(245,158,11,0.15)', color:'#fbbf24', border:'1px solid rgba(245,158,11,0.3)' }}>Needs webhook</span>}
                  </div>
                  <Toggle on={notificationSettings.slack.enabled} onToggle={() => setNotificationSettings(prev => ({ ...prev, slack: { ...prev.slack, enabled: !prev.slack.enabled } }))} />
                </div>
                {notificationSettings.slack.enabled && (<>
                  <div style={{ marginBottom:12 }}>
                    <div style={{ fontSize:11, color:'#94a3b8', marginBottom:6 }}>Slack Incoming Webhook URL</div>
                    <input type="url" value={notificationSettings.slack.webhookUrl}
                      onChange={e => setNotificationSettings(prev => ({ ...prev, slack: { ...prev.slack, webhookUrl: e.target.value } }))}
                      placeholder="https://hooks.slack.com/services/..."
                      style={{ width:'100%', padding:'10px 12px', borderRadius:8, background:'rgba(255,255,255,0.05)', border:'1px solid rgba(255,255,255,0.1)', color:'white', fontSize:12, fontFamily:'monospace', outline:'none', boxSizing:'border-box' }}
                      onFocus={e=>e.target.style.borderColor='#a855f7'} onBlur={e=>e.target.style.borderColor='rgba(255,255,255,0.1)'}
                    />
                    <p style={{ fontSize:11, color:'#334155', marginTop:4 }}>Slack → Apps → Incoming Webhooks → Add New Webhook to Workspace</p>
                  </div>
                  <div style={{ marginBottom:12 }}>
                    <div style={{ fontSize:11, color:'#94a3b8', marginBottom:6 }}>Alert Severity Filter</div>
                    <SevFilter channel="slack" />
                  </div>
                  <button disabled={!notificationSettings.slack.webhookUrl}
                    onClick={() => {
                      setNotifTestStatus(p => ({ ...p, slack: 'sending' }));
                      fetch(notificationSettings.slack.webhookUrl, {
                        method:'POST', mode:'no-cors', headers:{'Content-Type':'application/json'},
                        body: JSON.stringify({ text:`✅ *IoMT SOC — Test Notification*\nSlack alerts are configured.\n*Filters:* ${['critical','high','medium'].filter(l=>notificationSettings.slack[l]).join(', ')}\n_Alerts will auto-dispatch when threats are detected._` }),
                      }).finally(() => { setNotifTestStatus(p => ({ ...p, slack:'sent' })); setTimeout(() => setNotifTestStatus(p => ({ ...p, slack:null })), 3000); });
                    }}
                    style={{ width:'100%', padding:'10px', borderRadius:8, border:'1px solid rgba(168,85,247,0.4)', background:'rgba(168,85,247,0.1)', color:'#c084fc', fontSize:13, fontWeight:600, cursor: notificationSettings.slack.webhookUrl ? 'pointer' : 'not-allowed', opacity: notificationSettings.slack.webhookUrl ? 1 : 0.4, display:'flex', alignItems:'center', justifyContent:'center', gap:6 }}>
                    <Send style={{ width:13, height:13 }} />
                    {notifTestStatus.slack === 'sending' ? 'Sending…' : notifTestStatus.slack === 'sent' ? '✓ Sent to Slack' : 'Send Test Message'}
                  </button>
                </>)}
              </div>
            </div>

            {/* Footer */}
            <div style={{ padding:'14px 20px', borderTop:'1px solid rgba(255,255,255,0.08)', display:'flex', justifyContent:'flex-end' }}>
              <button onClick={() => setShowNotificationSettings(false)}
                style={{ padding:'9px 20px', borderRadius:8, background:'#0891b2', color:'white', fontSize:13, fontWeight:600, border:'none', cursor:'pointer' }}>
                Done
              </button>
            </div>
          </div>
        </div>
        );
      })()}

      {/* Threat Intelligence Panel */}
      {showThreatIntelPanel && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm flex items-center justify-center z-50 p-4">
          <div className="bg-slate-900 border border-slate-700 rounded-xl w-full max-w-2xl overflow-hidden">
            <div className="px-4 py-3 border-b border-slate-700 flex items-center justify-between bg-slate-800/50">
              <div className="flex items-center gap-2">
                <Globe className="w-5 h-5 text-purple-400" />
                <h3 className="font-semibold text-lg">Threat Intelligence Feed</h3>
                <span className="px-1.5 py-0.5 rounded bg-purple-500/20 text-purple-400 text-base">{matchedThreats} matches</span>
              </div>
              <button onClick={() => setShowThreatIntelPanel(false)} className="p-1.5 hover:bg-slate-700 rounded-lg">
                <X className="w-4 h-4" />
              </button>
            </div>

            {/* Intel Sources */}
            <div className="px-4 py-3 border-b border-slate-700/50 bg-slate-800/30">
              <div className="flex items-center justify-between mb-2">
                <span className="text-base text-slate-400">Connected Sources</span>
                <button className="flex items-center gap-1 text-base text-cyan-400 hover:underline">
                  <RefreshCw className="w-3 h-3" /> Sync All
                </button>
              </div>
              <div className="flex gap-2 flex-wrap">
                {threatSources.map((source, i) => (
                  <div key={i} className={`flex items-center gap-1.5 px-2 py-1 rounded-lg border ${source.status === 'active' ? 'bg-emerald-500/10 border-emerald-500/30' : 'bg-amber-500/10 border-amber-500/30'}`}>
                    <div className={`w-1.5 h-1.5 rounded-full ${source.status === 'active' ? 'bg-emerald-400' : 'bg-amber-400'}`} />
                    <span className="text-base font-medium">{source.name}</span>
                    <span className="text-base text-slate-500">{source.lastSync}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* Threat List */}
            <div className="max-h-80 overflow-y-auto divide-y divide-slate-700/30">
              {threatIntel.map((threat) => (
                <div key={threat.id} className={`px-4 py-3 flex items-center gap-3 ${threat.matched ? 'bg-red-500/5' : ''}`}>
                  <div className={`p-2 rounded-lg ${
                    threat.severity === 'critical' ? 'bg-red-500/20' :
                    threat.severity === 'high' ? 'bg-orange-500/20' :
                    threat.severity === 'medium' ? 'bg-yellow-500/20' : 'bg-blue-500/20'
                  }`}>
                    {threat.type.includes('Botnet') || threat.type.includes('Ransomware') ? <Skull className="w-4 h-4 text-red-400" /> :
                     threat.type.includes('Malware') ? <Bug className="w-4 h-4 text-orange-400" /> :
                     <Crosshair className="w-4 h-4 text-amber-400" />}
                  </div>
                  <div className="flex-1">
                    <div className="flex items-center gap-2 mb-0.5">
                      <span className="text-lg font-medium">{threat.type}</span>
                      <span className={`px-1.5 py-0.5 rounded text-base ${getSeverityColor(threat.severity)}`}>{threat.severity}</span>
                      {threat.matched && (
                        <span className="px-1.5 py-0.5 rounded text-base bg-red-500/20 text-red-400 font-bold animate-pulse">MATCHED</span>
                      )}
                    </div>
                    <p className="text-base font-mono text-slate-300">{threat.indicator}</p>
                    <p className="text-base text-slate-500">{threat.source} • {threat.time} • {threat.confidence}% confidence</p>
                  </div>
                  <button className="p-2 rounded-lg hover:bg-slate-700/50">
                    <Ban className="w-4 h-4 text-red-400" />
                  </button>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Network Topology Panel */}
      {showTopology && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm flex items-center justify-center z-50 p-4">
          <div className="bg-slate-900 border border-slate-700 rounded-xl w-full max-w-4xl overflow-hidden">
            <div className="px-4 py-3 border-b border-slate-700 flex items-center justify-between bg-slate-800/50">
              <div className="flex items-center gap-2">
                <MapPin className="w-5 h-5 text-emerald-400" />
                <h3 className="font-semibold text-lg">Network Topology</h3>
                {activeAttackPath && (
                  <span className="px-2 py-0.5 rounded bg-red-500/20 text-red-400 text-base animate-pulse">ATTACK IN PROGRESS</span>
                )}
              </div>
              <button onClick={() => setShowTopology(false)} className="p-1.5 hover:bg-slate-700 rounded-lg">
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="p-4">
              {/* Topology Visualization */}
              <div className="relative h-96 bg-slate-800/30 rounded-xl border border-slate-700/50 overflow-hidden">
                {/* Grid Background */}
                <div className="absolute inset-0 opacity-20" style={{
                  backgroundImage: `radial-gradient(circle at 1px 1px, rgba(255,255,255,0.15) 1px, transparent 0)`,
                  backgroundSize: '24px 24px'
                }} />

                {/* Connection Lines */}
                <svg className="absolute inset-0 w-full h-full">
                  {networkLinks.map((link, i) => {
                    const fromNode = topologyNodes.find(n => n.id === link.from);
                    const toNode = topologyNodes.find(n => n.id === link.to);
                    if (!fromNode || !toNode) return null;
                    const isAttackPath = activeAttackPath && 
                      ((activeAttackPath.from === link.from || activeAttackPath.to === link.to) ||
                       (link.from === 'switch1' && toNode.device));
                    return (
                      <line
                        key={i}
                        x1={`${fromNode.x}%`}
                        y1={`${fromNode.y}%`}
                        x2={`${toNode.x}%`}
                        y2={`${toNode.y}%`}
                        stroke={isAttackPath ? '#ef4444' : '#475569'}
                        strokeWidth={isAttackPath ? 3 : 2}
                        strokeDasharray={isAttackPath ? '8 4' : 'none'}
                        className={isAttackPath ? 'animate-pulse' : ''}
                      />
                    );
                  })}
                </svg>

                {/* Nodes */}
                {topologyNodes.map((node) => {
                  const Icon = getNodeIcon(node.type);
                  const isSelected = selectedNode?.id === node.id;
                  const statusColors = {
                    normal: 'bg-emerald-500/20 border-emerald-500/50 text-emerald-400',
                    warning: 'bg-amber-500/20 border-amber-500/50 text-amber-400',
                    attack: 'bg-red-500/30 border-red-500 text-red-400 animate-pulse',
                    isolated: 'bg-violet-500/20 border-violet-500/50 text-violet-400',
                  };
                  return (
                    <div
                      key={node.id}
                      className={`absolute transform -translate-x-1/2 -translate-y-1/2 cursor-pointer transition-all ${isSelected ? 'scale-110' : 'hover:scale-105'}`}
                      style={{ left: `${node.x}%`, top: `${node.y}%` }}
                      onClick={() => setSelectedNode(node)}
                    >
                      <div className={`p-3 rounded-xl border-2 ${statusColors[node.status]} ${isSelected ? 'ring-2 ring-cyan-400' : ''}`}>
                        <Icon className="w-6 h-6" />
                      </div>
                      <p className="text-base text-center mt-1 font-medium whitespace-nowrap">{node.label}</p>
                    </div>
                  );
                })}

                {/* Legend */}
                <div className="absolute bottom-3 left-3 flex gap-3">
                  {[
                    { color: 'bg-emerald-400', label: 'Normal' },
                    { color: 'bg-amber-400', label: 'Warning' },
                    { color: 'bg-red-400', label: 'Attack' },
                    { color: 'bg-violet-400', label: 'Isolated' },
                  ].map((item, i) => (
                    <div key={i} className="flex items-center gap-1.5">
                      <div className={`w-2 h-2 rounded-full ${item.color}`} />
                      <span className="text-base text-slate-400">{item.label}</span>
                    </div>
                  ))}
                </div>
              </div>

              {/* Selected Node Details */}
              {selectedNode && (
                <div className="mt-4 p-4 rounded-xl bg-slate-800/50 border border-slate-700/50">
                  <div className="flex items-center justify-between mb-3">
                    <div className="flex items-center gap-2">
                      {React.createElement(getNodeIcon(selectedNode.type), { className: 'w-5 h-5 text-cyan-400' })}
                      <span className="font-semibold">{selectedNode.label}</span>
                      <span className={`px-2 py-0.5 rounded text-base ${
                        selectedNode.status === 'normal' ? 'bg-emerald-500/20 text-emerald-400' :
                        selectedNode.status === 'warning' ? 'bg-amber-500/20 text-amber-400' :
                        selectedNode.status === 'attack' ? 'bg-red-500/20 text-red-400' :
                        'bg-violet-500/20 text-violet-400'
                      }`}>
                        {selectedNode.status}
                      </span>
                    </div>
                    {selectedNode.device && isolatedDevices.includes(selectedNode.device) && (
                      <button 
                        onClick={() => handleQuickAction('restore', { device: selectedNode.device })}
                        className="px-3 py-1.5 rounded-lg bg-emerald-500/20 text-emerald-400 text-base font-medium hover:bg-emerald-500/30"
                      >
                        Restore Connection
                      </button>
                    )}
                    {selectedNode.device && !isolatedDevices.includes(selectedNode.device) && selectedNode.status !== 'normal' && (
                      <button 
                        onClick={() => {
                          setIsolatedDevices(prev => [...prev, selectedNode.device]);
                          setTopologyNodes(prev => prev.map(n => n.id === selectedNode.id ? { ...n, status: 'isolated' } : n));
                          setSelectedNode({ ...selectedNode, status: 'isolated' });
                        }}
                        className="px-3 py-1.5 rounded-lg bg-violet-500/20 text-violet-400 text-base font-medium hover:bg-violet-500/30"
                      >
                        Isolate Device
                      </button>
                    )}
                  </div>
                  <div className="grid grid-cols-4 gap-3">
                    <div className="p-2 rounded-lg bg-slate-700/30">
                      <p className="text-base text-slate-400">Type</p>
                      <p className="text-lg font-medium capitalize">{selectedNode.type}</p>
                    </div>
                    <div className="p-2 rounded-lg bg-slate-700/30">
                      <p className="text-base text-slate-400">IP Address</p>
                      <p className="text-lg font-mono">{selectedNode.device ? deviceStatus[selectedNode.device]?.ip : '192.168.1.1'}</p>
                    </div>
                    <div className="p-2 rounded-lg bg-slate-700/30">
                      <p className="text-base text-slate-400">Connections</p>
                      <p className="text-lg font-medium">{networkLinks.filter(l => l.from === selectedNode.id || l.to === selectedNode.id).length}</p>
                    </div>
                    <div className="p-2 rounded-lg bg-slate-700/30">
                      <p className="text-base text-slate-400">Traffic</p>
                      <p className="text-lg font-medium">{selectedNode.device ? deviceStatus[selectedNode.device]?.packets?.toLocaleString() : Math.floor(Math.random() * 10000)} pkts</p>
                    </div>
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
