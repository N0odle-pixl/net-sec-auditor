import re
from collections import defaultdict
from datetime import datetime

class LogParser:
    def __init__(self, threshold=5):
        self.threshold = threshold
        self.failed_logins = defaultdict(list)
        
        self.auth_failed_regex = re.compile(
            r'^(?P<month>\w{3})\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})\s+'
            r'(?P<host>\S+)\s+(?P<service>sshd\[\d+\]):\s+'
            r'Failed password for (?:invalid user\s+)?(?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})',
            re.IGNORECASE
        )
        
        self.nginx_failed_regex = re.compile(
            r'^(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+-\s+-\s+'
            r'\[(?P<datetime>[^\]]+)\]\s+"(?P<method>\w+)\s+(?P<url>\S+)\s+(?P<protocol>[^"]+)"\s+'
            r'(?P<status>401|403)\s+(?P<bytes>\d+)',
            re.IGNORECASE
        )

    def parse_auth_line(self, line):
        match = self.auth_failed_regex.match(line)
        if match:
            data = match.groupdict()
            ip = data['ip']
            user = data['user']
            timestamp = f"{data['month']} {data['day']} {data['time']}"
            
            self.failed_logins[ip].append({
                'type': 'SSH_BRUTE_FORCE',
                'user': user,
                'timestamp': timestamp
            })

    def parse_nginx_line(self, line):
        match = self.nginx_failed_regex.match(line)
        if match:
            data = match.groupdict()
            ip = data['ip']
            url = data['url']
            status = data['status']
            timestamp = data['datetime']
            
            self.failed_logins[ip].append({
                'type': 'NGINX_AUTH_FAIL',
                'url': url,
                'status': status,
                'timestamp': timestamp
            })

    def analyze_logs(self, file_path, log_type='auth'):
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                if log_type == 'auth':
                    self.parse_auth_line(line)
                elif log_type == 'nginx':
                    self.parse_nginx_line(line)

    def detect_attacks(self):
        alerts = []
        for ip, events in self.failed_logins.items():
            if len(events) >= self.threshold:
                unique_users = set(e.get('user') for e in events if 'user' in e)
                
                if len(unique_users) > 1:
                    attack_type = "Credential Stuffing"
                else:
                    attack_type = "Brute-Force"
                    
                alerts.append({
                    'ip': ip,
                    'attack_type': attack_type,
                    'total_attempts': len(events),
                    'unique_usernames_targeted': len(unique_users),
                    'events': events
                })
        return alerts