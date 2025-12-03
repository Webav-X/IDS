# DetectionEngine.py

import os
import joblib
import pandas as pd
from collections import defaultdict

class DetectionEngine:
    def __init__(self,
                 model_path:  str   = r"C:/Users/Webhav/Desktop/pthon/ML Model/rf_model.joblib",
                 scaler_path: str   = r"C:/Users/Webhav/Desktop/pthon/ML Model/rf_scaler.joblib",
                 threshold:   float = 0.5):
        """
        Loads your RF scaler + model, integrates ML & legacy rules.
        """
        if not os.path.exists(scaler_path):
            raise FileNotFoundError(f"Scaler not found: {scaler_path}")
        if not os.path.exists(model_path):
            raise FileNotFoundError(f"Model not found: {model_path}")

        self.scaler    = joblib.load(scaler_path)
        self.model     = joblib.load(model_path)
        self.threshold = threshold

        self.feature_names = list(self.scaler.feature_names_in_)
        self.n_expected    = len(self.feature_names)

        # state for PROBE rules
        self.hosts_scanned = defaultdict(set)
        self.ports_scanned = defaultdict(set)

        self.rules = [
            self.rule_phf, self.rule_syn_flood, self.rule_neptune, 
            self.rule_smurf, self.rule_pod, self.rule_teardrop,
            self.rule_land_attack, self.rule_buffer_overflow,
            self.rule_ipsweep, self.rule_portsweep, self.rule_nmap,
            self.rule_satan, self.rule_back, self.rule_loadmodule,
            self.rule_multihop, self.rule_perl, self.rule_rootkit,
            self.rule_ftp_write, self.rule_guess_passwd, self.rule_imap,
            self.rule_spy, self.rule_warezclient, self.rule_warezmaster
        ]

        # order for raw feature vector before scaling
        self._feat_order = [
            'packet_size','packet_rate','byte_rate',
            'tcp_flags','fragmented','fragment_offset',
            'protocol','ttl','source_port','destination_port'
        ]

        print(f"[DetectionEngine] scaler expects {self.n_expected} features")

    def detect(self, f: dict) -> list:
        alerts = []

        # 1) ML-based
        ml = self._detect_ml(f)
        if ml:
            alerts.append(ml)

        # 2) legacy rules
        for rule in self.rules:
            res = rule(f)
            if res:
                alerts.append(res)

        return alerts

    def _detect_ml(self, f: dict):
        raw = [int(f.get(feat)) if isinstance(f.get(feat), bool) else f.get(feat, 0)
               for feat in self._feat_order]

        # pad/truncate
        if len(raw) < self.n_expected:
            raw += [0]*(self.n_expected - len(raw))
        else:
            raw = raw[:self.n_expected]

        df = pd.DataFrame([raw], columns=self.feature_names)
        Xs = self.scaler.transform(df)
        prob = float(self.model.predict_proba(Xs)[0][1])

        if prob >= self.threshold:
            return {'type':'Anomaly (ML)', 'rule':'rf_model', 'confidence':prob}
        return None

    def rule_syn_flood(self, f: dict):
        """
        Neptune SYN-Flood: delta-t based flood, threshold 100 pps.
        """
        SYN = 0x02
        if f['protocol']==6 and (f['tcp_flags'] & SYN)==SYN:
            if f['packet_rate'] > 100:
                return {
                    'type':       'SYN Flood',
                    'rule':       'syn_flood',
                    'confidence': min(1.0, f['packet_rate']/1000)
                }
        return None

    # rest of your rules unchanged...

    def rule_phf(self, f):
        PSH_ACK = 0x18
        if f['service']=='http' and (f['tcp_flags'] & PSH_ACK)==PSH_ACK and f['packet_rate']>20:
            return {'type':'PHF','rule':'phf','confidence':0.75}

    def rule_neptune(self, f):
        return self.rule_syn_flood(f)

    def rule_smurf(self, f):
        if f['protocol']==1 and f['destination_ip'].endswith('.255'):
            return {'type':'Smurf','rule':'smurf','confidence':0.90}

    def rule_pod(self, f):
        if f['protocol']==1 and f['packet_size']>1000:
            return {'type':'Ping of Death','rule':'pod','confidence':0.85}

    def rule_teardrop(self, f):
        if f['fragmented'] and f['fragment_offset']>500:
            return {'type':'Teardrop','rule':'teardrop','confidence':0.90}

    def rule_land_attack(self, f):
        if f['source_ip']==f['destination_ip'] and f['source_port']==f['destination_port']:
            return {'type':'LAND','rule':'land','confidence':0.95}

    def rule_buffer_overflow(self, f):
        if f['packet_size']>1500 and f['service'] in ('http','ftp','smtp'):
            return {'type':'Buffer Overflow','rule':'buffer_overflow','confidence':0.85}

    def rule_ipsweep(self, f):
        key=f['source_ip']; self.hosts_scanned[key].add(f['destination_ip'])
        if len(self.hosts_scanned[key])>10:
            return {'type':'IP Sweep','rule':'ipsweep','confidence':0.80}

    def rule_portsweep(self, f):
        key=(f['source_ip'],f['destination_ip'])
        self.ports_scanned[key].add(f['destination_port'])
        if len(self.ports_scanned[key])>10:
            return {'type':'Port Sweep','rule':'portsweep','confidence':0.80}

    def rule_nmap(self, f):
        key=(f['source_ip'],f['destination_ip'])
        self.ports_scanned[key].add(f['destination_port'])
        if len(self.ports_scanned[key])>20:
            return {'type':'Nmap Scan','rule':'nmap','confidence':0.90}

    def rule_satan(self, f):
        key=f['source_ip']; self.hosts_scanned[key].add(f['destination_ip'])
        if len(self.hosts_scanned[key])>100:
            return {'type':'Satan Scan','rule':'satan','confidence':0.88}

    def rule_back(self, f):
        if f['destination_port']==514:
            return {'type':'Back','rule':'back','confidence':0.80}

    def rule_loadmodule(self, f):
        if f['fragmented'] and f['service'] in ('ftp','http','smtp'):
            return {'type':'Loadmodule','rule':'loadmodule','confidence':0.75}

    def rule_multihop(self, f):
        if f.get('ttl',0)>128:
            return {'type':'Multihop','rule':'multihop','confidence':0.70}

    def rule_perl(self, f):
        if f['service']=='http' and f['packet_size']>2000:
            return {'type':'Perl','rule':'perl','confidence':0.70}

    def rule_rootkit(self, f):
        if f['service']=='ftp' and f['packet_size']>3000:
            return {'type':'Rootkit','rule':'rootkit','confidence':0.75}

    def rule_ftp_write(self, f):
        if f['service']=='ftp' and f['byte_rate']>500:
            return {'type':'FTP Write','rule':'ftp_write','confidence':0.85}

    def rule_guess_passwd(self, f):
        if f['destination_port'] in (22,23) and f['packet_rate']>5:
            return {'type':'Guess Password','rule':'guess_passwd','confidence':0.80}

    def rule_imap(self, f):
        if f['service']=='imap' and f['packet_rate']>10:
            return {'type':'IMAP','rule':'imap','confidence':0.80}

    def rule_spy(self, f):
        if f['service'] in ('http','ftp') and f['packet_rate']>50 and f['byte_rate']<50:
            return {'type':'Spy','rule':'spy','confidence':0.65}

    def rule_warezclient(self, f):
        if f['destination_port']==6667 and f['packet_rate']>5:
            return {'type':'Warezclient','rule':'warezclient','confidence':0.80}

    def rule_warezmaster(self, f):
        if f['destination_port']==102:
            return {'type':'Warezmaster','rule':'warezmaster','confidence':0.80}
