import re

LOG_PATTERN = re.compile(
    r'(?P<ip>\S+)\s+'
    r'\[(?P<timestamp>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+'
    r'(?P<endpoint>\S+)\s+'
    r'(?P<protocol>[^"]+)"\s+'
    r'(?P<status>\d{3})\s+'
    r'(?P<size>\d+|-)\s+'
    r'"(?P<referer>[^"]*)"\s+'
    r'"(?P<user_agent>[^"]*)"'
)

class LogEntry:
    """
    Represents a single parsed log entry with all its attributes.
    """
    def __init__(self, data_dict):
        self.ip = data_dict['ip']
        self.timestamp = data_dict['timestamp']
        self.method = data_dict['method']
        self.endpoint = data_dict['endpoint']
        self.protocol = data_dict['protocol']
        self.status = int(data_dict['status'])
        self.size = 0 if data_dict['size'] == '-' else int(data_dict['size'])
        self.referer = data_dict['referer']
        self.user_agent = data_dict['user_agent']

    def __repr__(self):
        return f"<LogEntry {self.ip} -> {self.method} {self.endpoint} [{self.status}]>"

    @classmethod
    def parse_line(cls, line):
        """
        Parses a single log line. 
        Returns a LogEntry object if successful, or None if the line is corrupted.
        """
        match = LOG_PATTERN.match(line)
        if not match:
            return None
        
        return cls(match.groupdict())
    
    def print_details(self, sample_number):
        """
        Prints the detailed attributes of the log entry in a readable format.
        """
        print(f"[Sample {sample_number}] Parsed Log Object Details:")
        print(f"  - Client IP:  {self.ip}")
        print(f"  - Timestamp:  {self.timestamp}")
        print(f"  - Request:    {self.method} {self.endpoint} {self.protocol}")
        print(f"  - Status:     {self.status}")
        print(f"  - Body Bytes: {self.size}")
        print(f"  - Referer:    {self.referer}")
        print(f"  - User Agent: {self.user_agent}")
        print("-" * 40)