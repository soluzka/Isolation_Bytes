import os
import logging
from dotenv import load_dotenv

# Make sure environment variables are loaded
load_dotenv()

# Get the HTTPBL_API_KEY from environment or config
from config import HTTPBL_API_KEY

def build_httpbl_query(ip_address):
    """
    Build the HTTP:BL DNS query for Project Honey Pot.
    Example: For IP 1.2.3.4 and key 'abc123', returns 'abc123.4.3.2.1.dnsbl.httpbl.org'
    
    Project Honey Pot API keys need to be registered at https://www.projecthoneypot.org/
    
    Args:
        ip_address: The IP address to check against the DNSBL
        
    Returns:
        The properly formatted DNS query string or None if the API key is invalid
    """
    # Try to get the key directly from environment as a fallback
    api_key = HTTPBL_API_KEY or os.environ.get('HTTPBL_API_KEY', '')
    
    # Validate the API key - Project Honey Pot keys are 12 characters
    if not api_key or len(api_key.strip()) != 12:
        logging.warning(f"Invalid HTTPBL_API_KEY: '{api_key}'. Keys must be exactly 12 characters. Get a valid key from https://www.projecthoneypot.org/")
        return None
        
    # Validate IP format
    if not ip_address or not isinstance(ip_address, str) or ip_address.count('.') != 3:
        logging.warning(f"Invalid IP address format: {ip_address}")
        return None
        
    try:
        # Reverse the octets of the IP address
        reversed_ip = '.'.join(reversed(ip_address.split('.')))
        return f"{api_key}.{reversed_ip}.dnsbl.httpbl.org"
    except Exception as e:
        logging.error(f"Error building HTTPBL query: {e}")
        return None

# Function to interpret the HTTPBL response
def interpret_httpbl_response(response):
    """
    Interpret the HTTP:BL response from Project Honey Pot.
    
    Response format: "<octet1>.<octet2>.<octet3>.<octet4>"
    - octet1: Always 127
    - octet2: Days since last activity (0-255)
    - octet3: Threat score (0-255, higher is worse)
    - octet4: Visitor type
        - 0: Search Engine
        - 1: Suspicious
        - 2: Harvester
        - 3: Comment Spammer
        - 4: Suspicious & Harvester
        - 5: Suspicious & Comment Spammer
        - 6: Harvester & Comment Spammer
        - 7: Suspicious & Harvester & Comment Spammer
    
    Returns a dictionary with the interpreted values
    """
    try:
        if not response or not isinstance(response, str):
            return {'status': 'error', 'message': 'Invalid response'}
            
        octets = response.split('.')
        if len(octets) != 4 or octets[0] != '127':
            return {'status': 'error', 'message': 'Invalid HTTPBL response format'}
            
        days = int(octets[1])
        threat = int(octets[2])
        type_code = int(octets[3])
        
        visitor_types = []
        if type_code & 1: visitor_types.append('suspicious')
        if type_code & 2: visitor_types.append('harvester')
        if type_code & 4: visitor_types.append('comment_spammer')
        if type_code == 0: visitor_types.append('search_engine')
        
        return {
            'status': 'listed',
            'days_since_last_activity': days,
            'threat_score': threat,
            'visitor_type_code': type_code,
            'visitor_types': visitor_types,
            'is_search_engine': type_code == 0,
            'is_suspicious': bool(type_code & 1),
            'is_harvester': bool(type_code & 2),
            'is_comment_spammer': bool(type_code & 4)
        }
    except Exception as e:
        return {'status': 'error', 'message': f'Error interpreting response: {e}'}

