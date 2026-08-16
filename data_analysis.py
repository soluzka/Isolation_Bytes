from collections import Counter
import json
import hashlib
import math
import os
import re
import subprocess
import winreg
from cryptography.fernet import Fernet

# Visualization imports. The application is a Flask server, not a desktop GUI;
# force a non-interactive backend so matplotlib never creates Tkinter objects
# that can be finalized from a worker thread during shutdown.
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import seaborn as sns

# Data processing imports
import pandas as pd
import numpy as np
from scipy import stats


# Provided data
data = '3=U³\\¬¶6|cò\\u000fã£Ü\\u001bn>]UãÊOM³YWl®cÕ\\u0017«ÔñqZ­ÓZÖø\\u005cæ\\u0017ÙGµZ.ôSv²­5\\u001f;ÌÍ¸Õ\'Ö<\\u001eYã.ËôðâøxãµtøªÓ3/VÍÆµrÜfÚczlzjÎvfñfÎÔO\\u00177iËG§tÍ£=ðÙ\\u0017ì±º+¼=êqÇV\\u005cG«ig\']+>geµÜñ\\u001e¶±§ÊÚx|<Í¸|¥ìáÚ.é\\u001bn£³¦]véeô<y¸ãÉã\\u001dò>Ö\\u001e¼Æv\'§êÌvtn6Ó¥³læ:µl\'>jélOfÇ7ÉkÌWÔ\\u001fSÕå\'§\\u001e\\u001fÉ®\\u001b§\\u001bnáx;Åô¥¶gu¦­ÊÍcÓÖÑ©¹ð¶KêÊ>\\u001b;9«ª|K¹\\u001eÜ£;.¶ÅWðø´Ü£Õæxs\\u005c®\\u005cìÌuÑÓimn²\\u001f6Ö\\u005c]VÓ¬êÆôðkcm\\u005cÚ¦|iv\\u001døUOK³.>xm6vf¹en²vMñ.OSkS:sM¶´\\u001f<;ð;\\u001e[q;67Myj]VÚcz²µM§Å³±¬O+òtm3­¦©ÓGn9y<ÇZ;\\u001eÅÚ>ÑÓØ²¹\\u001eÚY/Gãð³\\u001by£zÒÎNµxø\\u005c­Uám\\u001eÕVÎº67.z¼rÜc¹l³ÒñãNÎ³.Çfº9ñâ®l±¶<¶GÙ\\u0017§isêÚ¦øt«¥/él7:Õ¸ñ5>lñ[3æØ|SnGÑµ:>â;Ôj>-<WGN|¥W5uSã©mZømÇ3­S[¥v+m²¼VUìrÕxãYÙMWìc>3ÖØø¬Õ+Ó\\u001bmZÙÃ\\u001dØÍc«9ñæVËÌW<ÕY³:êqéiGÓ\\u005cÜéÖZgSÙNéÌnÌ=qø®ÃÓ6^<\\u0017ÍK[¥å\\u001dæÔWSs:®jvÊ^j«:ÍGñSåÑ[\\u005cÕ^\\u001b^¦Ú\\u000fÇrÇSÚ´yqì\\u001dã´yÉµ+>^j]Ysé¼ä;£­ZÇzrãV/ÅÓNvM«Ëi].§±;:ñ6Í¬ô-ºÅò±WÌ^Åy:Nvè­\\u000f¼cÖ5^ª\\u001f-ÖY=KñGÓ-Õ´ØUnÑ¶ªòÔôr¼<«.W5åm¥|Ñãª>fòØ7âñM§9^\\u000f^Åã±|eêÑÓr;¬ôV[SÇtÇ5znµ:7Mnq\\u001f6|ÆÍæK¹xã¸]+³NÇ£áñcÙÆìÊ[yK¼Nãx;¶[ÙÌkâ³\\u001eÅÜ´]-[Îr­Sò\\u001f\'>Ã|:mÆ|²ÉØ«£Ü£¶´Ír§3Ç<¶xñÊ­¦/âê<ôVµÒ/Mu+òØ§ªyj¹KÕfná|\\u001e­t\\u001flkÅkzNôÚtÌÔêjøÃËVu´uÌÙ|¼èêèÜ´mé¦«£ºqì¸¹+ÖèÜG\\u000fÜèË\\u001b\\u001bºxvÑg´OxËÒ\\u001f<[MÚô¥zÑ/âÖÑ­MæU­Y|5µ6¶xÓ©\\u001e³â®ä|Zg/á§rW©§\\u005cÙØ|ªn-Õª>MÇÑ/ªµtÎr¶Ø\\u001fâò[Ô\\u001f­iÇä³­´­µÖÌn¬mø3s3|jå¼É§\\u001bu¥ø©Oz<7|ÃÓf®\\u001bø\\u001bê3g.Ó±.¼eueô©ñg\\u001dÜ±ÚjWÆ7ry-ê²/Ìê+ÜÔ\\u001fìf[ðÍSåØ¼Ü±åeéWjOÃOÒÊ7è]Æ6­ÕØº6s;ÃñGË±éMãKºZæÚ\\u001e¹GêU\\u001f|èrv¸vqÖVô9nnÆè\\u001fÅ\\u001fKºµ¬º\\u001eµð/KW9ÙjÎU6ìÉ\\u001f\\u001eÕG;èÜi¼\\u001e^ávÃ¹£=¥3Ü3ktytºKÎòtÓ\\u000fº:^-µÑåfµYváòONO-ÙUµÆË3µ±¶©n<§ò'


def analyze_data(data):
    """
    Generate a Fernet key for encrypting the provided data.

    NOTE: This used to run a large amount of debug analysis (hex-dumping the
    entire input, computing entropy/chi-squared statistics, and rendering
    matplotlib plots to disk) on every call. Since the generated key never
    actually depended on that analysis, and callers invoke this per scanned/
    quarantined file, that overhead made scans and quarantining extremely
    slow (flooding logs with full file hex dumps), leaked unclosed
    matplotlib figures (RuntimeWarning: More than 20 figures have been
    opened), and has been observed to crash the server outright on large
    files. The analysis has been removed; this now just returns a fresh
    Fernet key as it always did.

    Args:
        data (str or bytes): The data to analyze.

    Returns:
        bytes: A newly generated Fernet key.
    """

    # Validate input data
    if not data:
        print('Error: Input data is empty. Please provide valid data.')
        return Fernet.generate_key()

    # Convert to bytes if data is a string
    if isinstance(data, str):
        data = data.encode('latin-1')  # Convert to bytes using latin-1 encoding

    # Compute entropy and character frequency from the actual data
    # and save updated plots to static/. Limit plotting to the first
    # 4 KB so large files do not slow down scans.
    sample = data[:4096]
    frequency = Counter(sample)
    total = len(sample) if sample else 1
    entropy = -sum((freq / total) * math.log2(freq / total) for freq in frequency.values() if freq > 0)
    print(f'Computed entropy: {entropy:.4f} for {len(sample)} bytes')

    try:
        os.makedirs('static', exist_ok=True)
        import warnings
        warnings.filterwarnings("ignore", category=UserWarning, message="Starting a Matplotlib GUI outside of the main thread will likely fail.")
        warnings.filterwarnings("ignore", category=FutureWarning, message="Passing `palette` without assigning `hue` is deprecated")

        freq_df = pd.DataFrame(list(frequency.items()), columns=['Byte', 'Count'])
        freq_df = freq_df.sort_values('Count', ascending=False).head(30)
        plt.figure(figsize=(12, 6))
        sns.barplot(x='Byte', y='Count', data=freq_df, hue='Byte', palette='viridis', legend=False)
        plt.title('Top 30 Character Frequencies')
        plt.xlabel('Byte Value')
        plt.ylabel('Count')
        plt.tight_layout()
        plt.savefig('static/char_freq.png')
        plt.close()

        plt.figure(figsize=(8, 4))
        sns.set_style('whitegrid')
        plt.plot([entropy], marker='o')
        plt.title('Entropy Visualization')
        plt.xlabel('Segment')
        plt.ylabel('Entropy')
        plt.grid()
        plt.savefig('static/entropy.png')
        plt.close()
    except Exception as e:
        print(f'Could not save analysis plots: {e}')

    return Fernet.generate_key()


def _analyze_data_debug(data):
    """Retained for reference: the original verbose debug analysis that used
    to run on every call to analyze_data(). Not called anywhere."""
    print('Initial Data Length:', len(data))  # Log the initial length of the data
    print('Raw Data (hex):', data.hex())  # Log the raw data in hex

    # Frequency analysis
    frequency = Counter(data)
    print('Character Frequency:', frequency)

    # --- Plot Character Frequency ---
    if frequency:
        # Prepare data for plotting
        freq_df = pd.DataFrame(list(frequency.items()), columns=['Byte', 'Count'])
        freq_df = freq_df.sort_values('Count', ascending=False)
        import warnings
        warnings.filterwarnings("ignore", category=UserWarning, message="Starting a Matplotlib GUI outside of the main thread will likely fail.")
        warnings.filterwarnings("ignore", category=FutureWarning, message="Passing `palette` without assigning `hue` is deprecated")
        plt.figure(figsize=(12, 6))
        # Use hue='Byte' and legend=False to future-proof against Seaborn deprecation
        sns.barplot(x='Byte', y='Count', data=freq_df.head(30), hue='Byte', palette='viridis', legend=False)
        plt.title('Top 30 Character Frequencies')
        plt.xlabel('Byte Value')
        plt.ylabel('Count')
        plt.tight_layout()
        os.makedirs('static', exist_ok=True)
        plt.savefig('static/char_freq.png')
        plt.close()

    # --- Header and Payload Extraction ---
    # The header is the first byte. The payload is everything after the header.
    header = data[0:1]
    print(f'Header (first byte): {header}')

    # Header validation: Only '3' (0x33) is considered valid for this format.
    # If your data format changes, update this check accordingly.
    if header != b'3':
        print(f'Warning: Unexpected header value: {header!r} (expected b"3" / 0x33)')

    if len(data) <= 1:
        print('Error: No payload found after header.')
        payload = b''
    else:
        payload = data[1:]
        print(f'Payload extracted after header (length={len(payload)} bytes).')

    # Grouped diagnostics for context
    print('Diagnostics:')
    print(f'  Header (hex): {header.hex()}')
    print(f'  Payload (hex, first 32 bytes): {payload[:32].hex()}...')
    print(f'  Full data (surrounding, hex): {data[max(0, 1 - 10):1 + len(payload) + 10].hex()}')

    # Search for specific patterns (only call once per pattern)
    search_for_pattern(data, b'3=U')  # Example pattern to search for

    # Entropy calculation
    total_chars = sum(frequency.values())
    expected_frequency = total_chars / len(frequency)
    entropy = -sum((freq / total_chars) * math.log2(freq / total_chars) for freq in frequency.values())
    print('Entropy:', entropy)

    # Print the actual byte values of the first few bytes of the data
    print('Actual byte values of the first few bytes:', data[:20]) 

    # Check if the first few bytes match the custom magic number
    # Use a raw bytes literal or escape the backslash for \u000f
    custom_magic_number = b'3=U\xb3\xac\xb66|c\xf2\\u000f\xe3\xa3\xdc'  # Ensure this matches the expected header
    # Alternatively, if you want the actual byte value 0x0f, use:
    # custom_magic_number = b'3=U\xb3\xac\xb66|c\xf2\x0f\xe3\xa3\xdc'
    print('Checking for custom magic number...')
    if data.startswith(custom_magic_number):
        print('File format identified: Custom File Format')
    else:
        print('File format could not be identified')

    # Known file headers (magic numbers)
    file_signatures = {
        b'\x89PNG': 'PNG Image',
        b'GIF8': 'GIF Image',
        b'\xFF\xD8': 'JPEG Image',
        b'%PDF': 'PDF Document',
        b'PK': 'ZIP Archive',
        b'RIFF': 'WAV/AVI File',
        b'\x7FELF': 'ELF Executable',
        b'\x42\x5A': 'BZ2 Compressed',
        b'TXT': 'Text File',
        b'\xFF\xFB': 'MP3 Audio',
        b'\x00\x00\x00\x20ftyp': 'MP4 Video',
        b'<!DOCTYPE html>': 'HTML Document',
        b'<?xml': 'XML Document',
        b'PK\x03\x04': 'ZIP Archive (File Header)',
        b'\x52\x61\x72\x21': 'RAR Archive',
        b'\x1F\x8B': 'GZIP Compressed',
        b'\x4D\x5A': 'EXE Executable',
        b'\x30\x26\xB2\x75': 'WMV Video',
        b'\x66\x74\x79\x70': 'FLV Video',
        b'\x7B\x5C': 'JSON Document',
        b'\x25\x50\x44\x46': 'PDF Document',
        b'\x4D\x53\x57\x4F': 'MS Word Document',
        b'\x4D\x53\x45\x58': 'MS Excel Document',
        b'\x4D\x53\x50\x50': 'MS PowerPoint Document',
        b'\x4D\x53\x41\x43': 'MS Access Database',
        b'\x4D\x53\x50\x53': 'MS Project File',
        b'\x4D\x53\x56\x42': 'MS Visio File',
        b'\x4D\x53\x49\x4D': 'MS Image File',
        b'\x4D\x53\x49\x43': 'MS Icon File',
        b'\x4D\x53\x49\x42': 'MS Bitmap File',
        b'\x4D\x53\x49\x50': 'MS Picture File',
        b'\x4D\x53\x49\x47': 'MS GIF File',
        b'\x4D\x53\x49\x4A': 'MS JPEG File',
        b'\x4D\x53\x49\x50\x4E\x47': 'MS PNG File',
        b'\x4D\x53\x49\x42\x4D\x50': 'MS BMP File',
        b'\x4D\x53\x49\x43\x4F\x4E': 'MS ICO File',
        b'\x4D\x53\x49\x43\x55\x52': 'MS CUR File',
        b'\x4D\x53\x49\x41\x4E\x49': 'MS ANI File',
    }

    # Update the file_signatures dictionary with additional known signatures
    file_signatures.update({
        b'3=U': 'Custom Format', 
        b'3=U\xb3': 'Possible Format', 
        # Add more signatures as necessary
    })

    # Check for known file signatures
    for signature, file_type in file_signatures.items():
        if data.startswith(signature):
            print(f'Identified file format: {file_type}')
            break
    else:
        print('File format could not be identified')

    # Define the packet structure according to the protocol
    packet_structure = {
        'header': {'type': 'byte', 'length': 1},
        'length': {'type': 'int', 'length': 4},
        'payload': {'type': 'bytes', 'length': None},  # Length will be defined by the 'length' field
        'checksum': {'type': 'byte', 'length': 1}
    }

    # Function to parse the packet based on the defined structure
    def parse_packet(data):
        print('Raw Data:', data)  # Print the raw data for debugging
        offset = 0
        parsed_data = {}
   
        # Print raw data for debugging in a readable format
        print('Raw data (hex):', data.hex())
   
        # Parse header
        parsed_data['header'] = data[offset:offset + packet_structure['header']['length']]
        offset += packet_structure['header']['length']
   
        # Print the header bytes
        header_bytes = parsed_data['header']
        print('Header Bytes (hex):', header_bytes.hex())
        print('Full Data (hex):', data.hex())
        print('Surrounding Data (hex):', data[max(0, offset - 10):offset + 10].hex())
   
        # Before extracting length
        print('Current Offset before length extraction:', offset)
   
        # Parse length using a new method
        length_bytes = data[offset:offset + 4]  # Read 4 bytes for the length
        print('Raw Length Bytes:', length_bytes)  # Print the raw length bytes
        print('Raw Length Bytes (hex):', length_bytes.hex())  # Print the raw length bytes in hex
        parsed_length = int.from_bytes(length_bytes, 'big')  # Change to big-endian
        print('Parsed Length (int):', parsed_length)  # Print the parsed length
        print('Parsed Length (hex):', parsed_length.to_bytes(4, 'little').hex())  # Print the parsed length in hex
        print('Parsed Length (bin):', bin(parsed_length))  # Print the parsed length in binary
        print('Parsed Length (oct):', oct(parsed_length))  # Print the parsed length in octal
        if parsed_length <= 0 or parsed_length > len(data) - offset:
            print(f"Error: Invalid payload length {parsed_length} at offset {offset}.")
            return parsed_data
   
        parsed_data['length'] = parsed_length
        offset += 4
   
        # Debugging information for length
        print('Parsed Length:', parsed_data['length'])
        print('Total Data Length:', len(data))
        print('Offset:', offset)
   
        try:
            # Parse payload
            parsed_data['payload'] = data[offset:offset + parsed_data['length']]
            offset += parsed_data['length']
   
            # Debugging information
            print('Parsed Data:', parsed_data)  # Print the entire parsed_data dictionary
        except IndexError as e:
            print(f"Error: {e}. Check data structure and length.")
            return parsed_data
   
        # Parse checksum
        parsed_data['checksum'] = data[offset:offset + packet_structure['checksum']['length']]
        print('Parsed Packet:', parsed_data)
   
        return parsed_data

    # Function to calculate checksum
    def calculate_checksum(data):
        return sum(data) % 256  # Simple checksum calculation (mod 256)

    # Call the parse_packet function with the data
    parsed_packet = parse_packet(data)
    print('Parsed Packet:', parsed_packet)

    # Calculate and validate the checksum
    if 'payload' in parsed_packet:
        calculated_checksum = calculate_checksum(parsed_packet['payload'])
        if calculated_checksum == parsed_packet['checksum'][0]:  # Assuming checksum is a single byte
            print('Checksum is valid.')
        else:
            print('Checksum is invalid.')
    else:
        print('Error: Payload not found in parsed packet.')

    # Frequency Test
    freq_deviation = {char: freq - expected_frequency for char, freq in frequency.items()}
    print('Frequency Test Deviation:')
    for char, deviation in freq_deviation.items():
        print(f'{char}: {deviation}')

    # Runs Test
    runs = 0
    last_char = None
    for char in data:
        if char != last_char:
            runs += 1
        last_char = char
    print(f'Runs Test: {runs} runs found.')

    # Chi-Squared Test
    chi_squared = sum((freq - expected_frequency) ** 2 / expected_frequency for freq in frequency.values())
    print(f'Chi-Squared Test Statistic: {chi_squared}')

    # Extract features
    features = {'entropy': entropy}
    features.update(frequency)
    df = pd.DataFrame(list(features.items()), columns=['Feature', 'Value'])
    print('Extracted Features:')
    print(df)

    # Visualize character frequencies
    plt.figure(figsize=(12, 6))
    sns.set_style('whitegrid')
    sns.barplot(x=list(frequency.keys()), y=list(frequency.values()))
    plt.title('Character Frequency Distribution')
    plt.xlabel('Characters')
    plt.ylabel('Frequency')
    plt.xticks(rotation=90)
    plt.tight_layout()
    plt.savefig('static/char_freq.png')
    print('Character frequency plot saved to static/char_freq.png')

    # Visualize entropy
    plt.figure(figsize=(8, 4))
    sns.set_style('whitegrid')
    plt.plot([entropy], marker='o')
    plt.title('Entropy Visualization')
    plt.xlabel('Segment')
    plt.ylabel('Entropy')
    plt.grid()
    plt.savefig('static/entropy.png')
    print('Entropy plot saved to static/entropy.png')

    # Always generate and return a Fernet key at the very end
    try:
        key = Fernet.generate_key()
        print(f'Generated key: {key.decode()}')
        return key
    except Exception as e:
        print(f'Error generating key: {e}')
        # Return a fallback key if something goes wrong (should never happen)
        return Fernet.generate_key()

def search_for_pattern(data, pattern):
    if pattern in data:
        print(f'Pattern {pattern} found in data.')
    else:
        print(f'Pattern {pattern} not found in data.')

def compute_entropy(data):
    """Compute Shannon entropy for a bytes-like object."""
    if not data:
        return 0.0
    from collections import Counter
    total = len(data)
    counts = Counter(data)
    entropy = 0.0
    for count in counts.values():
        p = count / total
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


MALWARE_FAMILIES = [
    'wannacry', 'emotet', 'trickbot', 'qakbot', 'qbot', 'dridex', 'locky',
    'notpetya', 'petya', 'ryuk', 'conti', 'revil', 'sodinokibi', 'blackcat',
    'alphv', 'babuk', 'hive', 'blackmatter', 'darkside', 'hancitor', 'icedid',
    'bokbot', 'sload', 'teslacrypt', 'cryptolocker', 'gandcrab', 'sekmet',
    'ragnarok', 'maze', 'dharma', 'phobos', 'xtbl', 'medusalocker', 'nefilim',
    'cobaltstrike', 'metasploit', 'mimikatz', 'azorult', 'lokibot', 'remcos',
    'nanocore', 'darkcomet', 'njrat', 'quasar', 'asyncrat', 'warzone',
    'revengerat', 'predatorthethief', 'stealer', 'agenttesla', 'formbook',
    'xloader', 'redline', 'raccoon', 'vidar', 'stealc', 'lumma', 'prilex',
    'snakelogger', 'smokeloader', 'grandoreiro', 'buer', 'pikabot',
    'apt', 'apt1', 'apt28', 'apt29', 'lazarus', 'fin7', 'molerats',
    'charmingkitten', 'turla', 'apt34', 'apt35', 'apt40', 'apt41',
    'equation', 'regin', 'stuxnet', 'duqu', 'flame', 'gauss', 'tilded',
    # Ransomware families
    'lockbit', 'play', 'royal', 'akira', 'blackbasta', 'cuba', 'monti',
    'incransom', 'bianlian', 'donex', 'vhd', 'fog', 'vex', 'inter',
    'jigsaw', 'cerber', 'cryptowall', 'cryptxxx', 'ctblocker', 'globe',
    'maktub', 'petya', 'saturn', 'shaded', 'spora', 'troldesh', 'wildfire',
    'xorist', 'zzzz', 'badrabbit', 'satana', 'wannacrypt',
    # Banking / info stealers
    'zeus', 'citadel', 'spyeye', 'carberp', 'shifu', 'bebloh', 'caphaw',
    'dyre', 'bugat', 'heodo', 'tinba', 'vawtrak', 'neverquest', 'kronos',
    'osiris', 'urlzone', 'gozi', 'matsnu', 'murofet', 'fobber', 'xdedic',
    'hawkeye', 'lokibot', 'formbook', 'agenttesla', 'redline', 'raccoon',
    'vidar', 'stealc', 'lumma', 'prilex', 'snakelogger', 'azorult',
    'grandoreiro', 'ursnif', 'gootkit', 'flubot', 'teabot', 'copperstealer',
    # RATs / backdoors
    'njrat', 'asyncrat', 'quasar', 'warzone', 'revengerat', 'darkcomet',
    'nanocore', 'remcos', 'proton', 'adwind', 'alien', 'ap0calypse',
    'beast', 'bifrost', 'blackshades', 'bluebanana', 'bozok', 'cybergate',
    'dendroid', 'desertfalcon', 'diamondfox', 'ghostrat', 'glacier',
    'jrat', 'netwire', 'poisonivy', 'pupy', 'shadowpad', 'spynote',
    'sub7', 'xtreme', 'xagent', 'comrat', 'carbon', 'invisimole',
    'empire', 'p0wn', 'chthonic', 'dridex', 'trickbot', 'emotet',
    # Miners
    'xmrig', 'minerd', 'cpuminer', 'nicehash', 'minergate', 'stratum',
    'nanopool', 'xmrrig', 'xmrstak', 'ccminer', 'sgminer', 'cgminer',
    'claymore', 'phoenixminer', 'trex', 'nbminer', 'gminer', 'lolminer',
    # IoT / botnets
    'mirai', 'satori', 'owari', 'masuta', 'reaper', 'hajime', 'brickerbot',
    'gafgyt', 'fbot', 'tsunami', 'moobot', 'bigpipe', 'demonbot',
]


def yara_risk_score(rule_names):
    """Map YARA rule names to a 0-100 risk contribution.

    Rules are grouped by severity. The score is capped at 100.
    """
    if not rule_names:
        return 0.0
    score = 0.0
    for rule in rule_names:
        name = rule.lower()
        # Malware families use word-boundary matching to avoid substring false positives (e.g. "apt" inside "adapt").
        if any(re.search(r'\\b' + re.escape(family) + r'\\b', name) for family in MALWARE_FAMILIES):
            score += 40.0
        elif re.search(r'\\b(ransomware|persistence|credential)\\b', name):
            score += 35.0
        elif re.search(r'\\b(trojan|backdoor|rat)\\b', name):
            score += 25.0
        elif re.search(r'\\b(dropper|loader|downloader)\\b', name):
            score += 20.0
        elif re.search(r'\\b(adware|pua|pup)\\b', name):
            score += 10.0
        elif re.search(r'\\b(info|helper|tool)\\b', name):
            score += 5.0
        else:
            score += 15.0
    return min(100.0, score)


MITRE_TECHNIQUES = {
    'ransomware': 'TA0040 (Impact)',
    'persistence': 'TA0003 (Persistence)',
    'credential': 'TA0006 (Credential Access)',
    'trojan': 'TA0011 (Command and Control)',
    'backdoor': 'TA0011 (Command and Control)',
    'rat': 'TA0011 (Command and Control)',
    'dropper': 'TA0023 (Resource Development)',
    'loader': 'TA0023 (Resource Development)',
    'downloader': 'TA0010 (Exfiltration)',
    'adware': 'TA0042 (Resource Development)',
    'pua': 'TA0042 (Resource Development)',
    'pup': 'TA0042 (Resource Development)',
    'stealer': 'TA0006 (Credential Access)',
    'keylogger': 'TA0006 (Credential Access)',
    'apt': 'TA0043 (Reconnaissance)',
    'cobaltstrike': 'TA0011 (Command and Control)',
    'mimikatz': 'TA0006 (Credential Access)',
    'emotet': 'TA0008 (Lateral Movement)',
    'trickbot': 'TA0006 (Credential Access)',
    'qakbot': 'TA0008 (Lateral Movement)',
    'dridex': 'TA0006 (Credential Access)',
    'wannacry': 'TA0040 (Impact)',
    'notpetya': 'TA0040 (Impact)',
    'lockbit': 'TA0040 (Impact)',
    'miner': 'TA0049 (Impact)',
    'xmrig': 'TA0049 (Impact)',
}


def yara_mitre_tags(rule_names):
    """Return a list of MITRE ATT&CK technique tags for the matched YARA rules."""
    if not rule_names:
        return []
    tags = set()
    for rule in rule_names:
        name = rule.lower()
        for keyword, tag in MITRE_TECHNIQUES.items():
            if re.search(r'\\b' + re.escape(keyword) + r'\\b', name):
                tags.add(tag)
    return sorted(tags)


PACKED_ENCODERS = [
    'upx', 'aspack', 'pecompact', 'fsg', 'mpress', 'petite', 'telock',
    'themida', 'winlicense', 'vmprotect', 'enigma', 'execryptor', 'armadillo',
    'obsidium', 'krypton', 'shrinker', 'neolite', 'pespin', 'rlpack',
    'nspack', 'expressor', 'acprotect', 'sdprotect', 'xcrypt', 'y0da',
    'dingboy', 'wxpack', 'andpakk', 'lamecrypt', 'noreborg', 'pep', 'bxp',
    'mew', 'bero', 'morphine', 'hackshield', 'themida', 'safengine',
    'securom', 'starforce', 'tages', 'protectdisc', 'cdilla',
    'packed', 'packed2', 'packer', 'cryptor', 'protector',
]


def packed_encoder_score(file_path, sample=8192):
    """Return a small risk score if the file contains known packer/encoder names."""
    if not os.path.exists(file_path):
        return 0.0
    try:
        with open(file_path, 'rb') as f:
            data = f.read(sample)
        lowered = data.lower()
        score = 0.0
        for name in PACKED_ENCODERS:
            if name.encode() in lowered:
                score += 5.0
        return min(30.0, score)
    except Exception:
        return 0.0


EXPLOIT_MARKERS = {
    b'cve-': 'CVE Reference',
    b'eternalblue': 'EternalBlue (MS17-010)',
    b'printnightmare': 'PrintNightmare',
    b'log4j': 'Log4j RCE',
    b'proxylogon': 'ProxyLogon',
    b'proxyshell': 'ProxyShell',
    b'sigred': 'SIGRed',
    b'zerologon': 'Zerologon',
    b'petitpotam': 'PetitPotam',
    b'sambacry': 'SambaCry',
    b'shellshock': 'Shellshock',
    b'heartbleed': 'Heartbleed',
    b'bluekeep': 'BlueKeep',
    b'bluekeep-dbg': 'BlueKeep',
    b'ms17-010': 'MS17-010',
    b'ms14-058': 'MS14-058',
    b'ms15-051': 'MS15-051',
    b'ms16-032': 'MS16-032',
    b'rop chain': 'ROP Chain',
    b'nop sled': 'NOP Sled',
    b'buffer overflow': 'Buffer Overflow',
    b'heap spray': 'Heap Spray',
    b'use-after-free': 'Use-After-Free',
    b'skeleton key': 'Skeleton Key',
    b'dcsync': 'DCSync',
    b'kerberoast': 'Kerberoasting',
    b'as-rep roast': 'AS-REP Roasting',
    b'pass the hash': 'Pass-the-Hash',
    b'pass the ticket': 'Pass-the-Ticket',
    b'golden ticket': 'Golden Ticket',
    b'silver ticket': 'Silver Ticket',
    b'unconstrained delegation': 'Unconstrained Delegation',
    b'rbcd': 'Resource-Based Constrained Delegation',
    b'exploit-db': 'Exploit-DB',
    b'proof of concept': 'Proof of Concept',
    b'poc ': 'Proof of Concept',
    b'n-day': 'N-Day Exploit',
    b'0-day': 'Zero-Day',
}


def exploit_score(file_path, sample=8192):
    """Return a risk score if the file contains exploit/PoC references."""
    if not os.path.exists(file_path):
        return 0.0
    try:
        with open(file_path, 'rb') as f:
            data = f.read(sample)
        lowered = data.lower()
        score = 0.0
        for marker, label in EXPLOIT_MARKERS.items():
            if marker in lowered:
                if b'cve-' in marker or b'ms' in marker[:3]:
                    score += 3.0
                else:
                    score += 8.0
        return min(30.0, score)
    except Exception:
        return 0.0


DEFAULT_IOCS = {
    'ips': [],
    'domains': [],
    'urls': [],
    'sha256': []
}


def _load_iocs():
    runtime_dir = os.environ.get('ANTIVIRUS_RUNTIME_DIR', os.path.dirname(os.path.abspath(__file__)))
    ioc_path = os.path.join(runtime_dir, 'iocs.json')
    if not os.path.exists(ioc_path):
        return DEFAULT_IOCS
    try:
        with open(ioc_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return DEFAULT_IOCS


def network_ioc_score(file_path, iocs=None, sample=128 * 1024):
    """Return a risk score if the file contains known bad IPs, domains or URLs."""
    if not os.path.exists(file_path):
        return 0.0
    if iocs is None:
        iocs = _load_iocs()
    try:
        with open(file_path, 'rb') as f:
            data = f.read(sample)
        lowered = data.lower()
        score = 0.0
        for ip in iocs.get('ips', []):
            if ip.lower().encode() in lowered:
                score += 15.0
        for domain in iocs.get('domains', []):
            if domain.lower().encode() in lowered:
                score += 10.0
        for url in iocs.get('urls', []):
            if url.lower().encode() in lowered:
                score += 12.0
        return min(40.0, score)
    except Exception:
        return 0.0


CVE_KB_MAP = {
    'eternalblue': ['KB4012598', 'KB4012606', 'KB4013198', 'KB4013429', 'KB4018466',
                    'KB4012212', 'KB4012213', 'KB4012214', 'KB4012215', 'KB4012216', 'KB4012217'],
    'ms17-010': ['KB4012598', 'KB4012606', 'KB4013198', 'KB4013429', 'KB4018466',
                 'KB4012212', 'KB4012213', 'KB4012214', 'KB4012215', 'KB4012216', 'KB4012217'],
    'printnightmare': ['KB5004945', 'KB5004950', 'KB5004951', 'KB5004953', 'KB5004954',
                       'KB5004955', 'KB5004956', 'KB5004958', 'KB5004959', 'KB5004960', 'KB5004961'],
    'log4j': [],  # Java library; no single Windows patch
    'proxylogon': ['KB5000871', 'KB5000953', 'KB5000960', 'KB5000978'],
    'proxyshell': ['KB5001779', 'KB5004780', 'KB5004791'],
    'sigred': ['KB4558998', 'KB4565503', 'KB4565511', 'KB4565513', 'KB4565529'],
    'zerologon': ['KB4577668', 'KB4577670', 'KB4577671', 'KB4577683', 'KB4577669'],
    'petitpotam': ['KB5005413', 'KB5005399', 'KB5005405', 'KB5005394', 'KB5005393',
                   'KB5005404', 'KB5005403', 'KB5005408', 'KB5005407', 'KB5005406'],
    'sambacry': [],  # Linux/Samba
    'shellshock': [],  # Bash
    'heartbleed': [],  # OpenSSL
    'bluekeep': ['KB4499175', 'KB4499164', 'KB4499149', 'KB4499180', 'KB4499172',
                 'KB4499179', 'KB4499167'],
    'ms14-058': ['KB3000061', 'KB3000869', 'KB3001554'],
    'ms15-051': ['KB3051761', 'KB3055642'],
    'ms16-032': ['KB3143141', 'KB3143145'],
    'ms17-010': ['KB4012598', 'KB4012606', 'KB4013198', 'KB4013429', 'KB4018466'],
}


def get_installed_kb_patches():
    """Return a set of installed Windows KB numbers from wmic qfe."""
    try:
        output = subprocess.check_output(
            ['wmic', 'qfe', 'get', 'HotFixID', '/format:csv'],
            shell=False,
            timeout=30,
            stderr=subprocess.STDOUT
        )
        text = output.decode('utf-8', errors='replace')
        installed = set()
        for line in text.splitlines():
            parts = line.split(',')
            if len(parts) >= 2:
                kb = parts[-1].strip().strip('"')
                if kb.upper().startswith('KB'):
                    installed.add(kb.upper())
        return installed
    except Exception as e:
        logging = __import__('logging')
        logging.getLogger('data_analysis').warning(f'Failed to query installed KB patches: {e}')
        return set()


def missing_critical_patches():
    """Return a list of (exploit_name, required_kbs) for unpatched critical CVEs."""
    installed = get_installed_kb_patches()
    missing = []
    for exploit, kbs in CVE_KB_MAP.items():
        if not kbs:
            continue
        if not any(kb.upper() in installed for kb in kbs):
            missing.append((exploit, kbs))
    return missing


def _hash_sha256(file_path):
    """Return the SHA-256 hash of a file."""
    import hashlib
    h = hashlib.sha256()
    try:
        with open(file_path, 'rb') as f:
            while True:
                chunk = f.read(1024 * 1024)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None


def load_trusted_hashes():
    """Load a set of trusted SHA-256 hashes from trusted_hashes.json."""
    runtime_dir = os.environ.get('ANTIVIRUS_RUNTIME_DIR', os.path.dirname(os.path.abspath(__file__)))
    path = os.path.join(runtime_dir, 'trusted_hashes.json')
    if not os.path.exists(path):
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'trusted_hashes.json')
    if not os.path.exists(path):
        return set()
    try:
        with open(path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        if isinstance(data, list):
            return set(h.lower() for h in data if isinstance(h, str))
        if isinstance(data, dict):
            sha_list = data.get('sha256', [])
            if isinstance(sha_list, list):
                return set(h.lower() for h in sha_list if isinstance(h, str))
            return set(v.lower() for v in data.values() if isinstance(v, str))
    except Exception:
        return set()


def is_trusted_file(file_path, trusted_hashes=None):
    """Return True if the file's SHA-256 is in the trusted hashes set."""
    if trusted_hashes is None:
        trusted_hashes = load_trusted_hashes()
    sha256 = _hash_sha256(file_path)
    if not sha256:
        return False
    return sha256.lower() in trusted_hashes


def compute_file_entropy(file_path, sample_bytes=1024 * 1024):
    """Read up to sample_bytes from a file and return its entropy."""
    if not os.path.exists(file_path):
        return 0.0
    try:
        with open(file_path, 'rb') as f:
            data = f.read(sample_bytes)
        return compute_entropy(data)
    except Exception:
        return 0.0


FILE_SIGNATURES = {
    b'\x89PNG': 'PNG Image',
    b'GIF8': 'GIF Image',
    b'\xFF\xD8': 'JPEG Image',
    b'%PDF': 'PDF Document',
    b'PK\x03\x04': 'ZIP Archive',
    b'PK': 'ZIP/MSI Archive',
    b'RIFF': 'WAV/AVI File',
    b'\x7FELF': 'ELF Executable',
    b'\x42\x5A': 'BZ2 Compressed',
    b'\xFF\xFB': 'MP3 Audio',
    b'\x00\x00\x00\x20ftyp': 'MP4 Video',
    b'<!DOCTYPE html>': 'HTML Document',
    b'<?xml': 'XML Document',
    b'\x52\x61\x72\x21': 'RAR Archive',
    b'\x1F\x8B': 'GZIP Compressed',
    b'\x4D\x5A': 'EXE/PE Executable',
    b'\x30\x26\xB2\x75': 'WMV Video',
    b'\x66\x74\x79\x70': 'FLV Video',
    b'\x7B\x5C': 'JSON Document',
    b'\x25\x50\x44\x46': 'PDF Document',
    b'MZ': 'MS-DOS/PE Executable',
    b'\xFE\xEF': 'SQL Server DB',
    b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1': 'Microsoft Compound',
    b'\x50\x4B\x05\x06': 'ZIP (empty)',
    b'\x37\x7A\xBC\xAF\x27\x1C': '7-Zip Archive',
    b'\xFD\x37\x7A\x58\x5A\x00': 'XZ Compressed',
    b'BZh': 'BZIP2 Compressed',
    b'\x1F\x9D': 'LZW/Z Compressed',
    b'\x1F\xA0': 'LZH/Z Huf',
    b'IC': 'ICQ Archive',
    b'\.\xAF\xBC\xC0': 'GPG',
    b'-----BEGIN PGP': 'PGP ASCII',
    b'# Microsoft': 'PEF/CAB',
    b'<?php': 'PHP Script',
    b'<html': 'HTML Page',
    b'<script': 'HTML/JS',
    b'{"': 'JSON Data',
    b'#!': 'Shell Script',
    b'@echo': 'Batch Script',
    b'registry': 'Windows Registry',
    b'\xCA\xFE\xBA\xBE': 'Java Class',
    b'PK\x07\x08': 'ZIP Archive',
    b'\x4C\x01': 'OBJ/COFF',
    b'\x5A\x4D': 'MS-DOS Executable',
    # Additional media / archive / document signatures
    b'ftypisom': 'MP4/ISO Media',
    b'ftypmp42': 'MP4 Video',
    b'ftypqt  ': 'QuickTime',
    b'\x00\x00\x01\xBA': 'MPEG/VOB',
    b'\x00\x00\x01\xB3': 'MPEG Video',
    b'OggS': 'Ogg Media',
    b'fLaC': 'FLAC Audio',
    b'ID3': 'MP3 Audio',
    b'\xFF\xF1': 'AAC Audio',
    b'\xFF\xF9': 'AAC Audio',
    b'\x49\x44\x33': 'MP3 Audio',
    b'\x4F\x67\x67\x53': 'Ogg Audio',
    b'\x42\x4D': 'BMP Image',
    b'\x47\x49\x46\x38': 'GIF Image',
    b'\xFF\xD8\xFF\xE0': 'JPEG Image',
    b'\xFF\xD8\xFF\xE1': 'JPEG Image',
    b'\xFF\xD8\xFF\xEE': 'JPEG Image',
    b'\xFF\xD8\xFF\xDB': 'JPEG Image',
    b'\x75\x73\x74\x61\x72': 'TAR Archive',
    b'\x1F\x8B\x08': 'GZIP Compressed',
    b'\x28\xB5\x2F\xFD': 'Zstandard',
    b'Rar!': 'RAR Archive',
    b'xar!': 'XAR Archive',
    b'\xD4\xC3\xB2\xA1': 'PCAP Capture',
    b'\xA1\xB2\xC3\xD4': 'PCAP Capture',
    b'\x0A\x0D\x0D\x0A': 'PCAPNG Capture',
    b'\x7B\x0D\x0A\x20\x22': 'JSON Data',
    b'\x2D\x2D\x2D\x2D\x2D\x42\x45\x47\x49\x4E': 'PEM/Key Data',
    b'-----BEGIN RSA PRIVATE KEY-----': 'RSA Private Key',
    b'-----BEGIN OPENSSH PRIVATE KEY-----': 'SSH Private Key',
    b'-----BEGIN CERTIFICATE-----': 'X509 Certificate',
    # Microsoft Office and common Windows/Adobe formats
    b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1': 'Microsoft Compound (DOC/XLS/PPT)',
    b'\x50\x4B\x05\x06': 'ZIP (empty)',
    b'\x50\x4B\x07\x08': 'ZIP (spanned)',
    b'MSWordDoc': 'Word Document',
    b'Word.Document.': 'Word Document',
    b'Excel.Sheet': 'Excel Spreadsheet',
    b'PowerPoint.Show': 'PowerPoint Presentation',
    b'%PDF-1.0': 'PDF Document',
    b'%PDF-1.1': 'PDF Document',
    b'%PDF-1.2': 'PDF Document',
    b'%PDF-1.3': 'PDF Document',
    b'%PDF-1.4': 'PDF Document',
    b'%PDF-1.5': 'PDF Document',
    b'%PDF-1.6': 'PDF Document',
    b'%PDF-1.7': 'PDF Document',
    b'%PDF-2.0': 'PDF Document',
    b'%!PS-Adobe': 'PostScript Document',
    b'%!PS': 'PostScript Document',
    # Images
    b'II*\x00': 'TIFF Image',
    b'MM\x00*': 'TIFF Image',
    b'\x00\x00\x00\x0C\x6A\x50\x20\x20\x0D\x0A\x87\x0A': 'JPEG 2000',
    b'RIFF\x00\x00\x00\x00WEBP': 'WebP Image',
    b'\x52\x49\x46\x46': 'RIFF Container',
    b'\xFF\x0A': 'JPEG XL',
    b'\x00\x00\x01\x00': 'ICO Icon',
    b'<?xml version="1.0"?><svg': 'SVG Image',
    b'<svg ': 'SVG Image',
    b'\x89\x48\x44\x46\x0D\x0A\x1A\x0A': 'HDF5 Data',
    # Disk / archive / container images
    b'\x43\x44\x30\x30\x31': 'ISO Image',
    b'\x45\x46\x49\x20\x50\x41\x52\x54': 'EFI Partition',
    b'\x55\x44\x46\x62\xA4': 'UDF Image',
    b'Concordance': 'DMG Disk Image',
    b'KDMV': 'VMDK Disk',
    b'VHDXFILE': 'VHDX Disk',
    b'\x63\x6F\x6E\x6E\x65\x63\x74\x69\x78': 'VHD Disk',
    b'\x78\x61\x72\x21': 'XAR Archive',
    b'\x4D\x53\x57\x49\x4D': 'WIM Image',
    b'\x78\x01\x73\x0D\x62\x62\x60': 'DMG/Zlib',
    # Flash and legacy web
    b'CWS': 'Flash SWF (compressed)',
    b'FWS': 'Flash SWF',
    b'ZWS': 'Flash SWF (LZMA)',
    # Scripts / source files
    b'using System;': 'C# Source',
    b'using namespace': 'C++/C# Source',
    b'#include <': 'C/C++ Source',
    b'import ': 'Python/Java Source',
    b'def ': 'Python Source',
    b'package ': 'Java Source',
    b'<?xml version=': 'XML Document',
    b'<!--': 'XML/HTML Comment',
    # Obscure / legacy / game / mobile / database
    b'\xFE\xED\xFA\xCE': 'Mach-O 32-bit',
    b'\xFE\xED\xFA\xCF': 'Mach-O 64-bit',
    b'\xCA\xFE\xBA\xBE': 'Mach-O Universal',
    b'\xBE\xBA\xFE\xCA': 'Mach-O Universal (reversed)',
    b'\xCF\xFA\xED\xFE': 'Mach-O 64-bit (reversed)',
    b'\xCE\xFA\xED\xFE': 'Mach-O 32-bit (reversed)',
    b'\x64\x65\x78\x0A\x30\x33\x35\x00': 'Android DEX',
    b'\x7F\x45\x4C\x46': 'ELF 32/64',
    b'\x01\x4C': 'COFF i386',
    b'\x4C\x01': 'COFF i386 (reversed)',
    b'\x01\x64': 'COFF x64',
    b'\x64\x01': 'COFF x64 (reversed)',
    b'\x66\x01': 'COFF 64+ (reversed)',
    b'000003F3': 'Amiga Hunk',
    b'NEO': 'Atari NEO',
    b'NES\x1A': 'NES ROM',
    b'SEGA GENESIS': 'Mega Drive ROM',
    b'PS-X EXE': 'PlayStation 1 EXE',
    b'XBEH': 'Xbox XBE',
    b'XEX1': 'Xbox 360 XEX',
    b'XEX2': 'Xbox 360 XEX',
    b'NTR': 'Nintendo DS ROM',
    b'AGB\x0E': 'Game Boy Advance ROM',
    b'MThd': 'MIDI Audio',
    b'Rar!\x1A\x07\x01\x00': 'RAR5 Archive',
    b'Rar!\x1A\x07\x00\x00': 'RAR4 Archive',
    b'BOOKMOBI': 'MOBI/AZW eBook',
    b'TEXtREAd': 'Palm PDB eBook',
    b'MSCF': 'CAB Archive',
    b'ISc(': 'CAB Archive (InstallShield)',
    b'ITSF': 'Compiled HTML (CHM)',
    b'ITOLITLS': 'Microsoft Reader LIT',
    b'Standard Jet DB': 'Access MDB',
    b'\x00\x01\x00\x00Standard Ace DB': 'Access ACCDB',
    b'!BDN': 'Outlook PST/OST',
    b'\x4C\x00\x00\x00\x01\x14\x02\x00': 'Windows LNK',
    b'[InternetShortcut]': 'URL Shortcut',
    b'SQLite format 3\x00': 'SQLite Database',
    b'hsqs': 'SquashFS Image',
    b'-rom1fs-': 'RomFS Image',
    b'CRAM': 'CRAM File',
    b'BAM\x01': 'BAM Sequence',
    b'BCF\x02': 'BCF Sequence',
    b'##fileformat=VCFv4': 'VCF Variant',
    b'>': 'FASTA Sequence',
    b'@': 'FASTQ Sequence',
    b'LOCUS       ': 'GenBank Record',
    b'dirc': 'Git Index',
    b'0x\x0A\x0D': 'Gopher Bookmark',
    b'\x04"M\x18': 'LZ4 Frame',
    b'\x28\xB5\x2F\xFD': 'Zstandard',
    b'\xFD\x37\x7A\x58\x5A\x00': 'XZ Archive',
    b'<parallels_disk_image>~': 'Parallels HDD',
    b'\x54\x41\x50\x45\x00\x00': 'Microsoft Tape Format',
    b'\x50\x41\x52\x31': 'PAR Archive',
    b'\x4D\x53\x54\x41\x44\x44\x49\x4E': 'MS Theater',
    b'\x00\x01\x00\x00\x00': 'Palm OS PRC',
    b'\x00\x01\x00\x08\x00': 'Palm OS PQA',
    b'\x00\x00\x00\x0C\x4A\x58\x4C\x20\x0D\x0A\x87\x0A': 'JPEG XL',
    b'\x52\x49\x46\x46\x00\x00\x00\x00\x41\x43\x4F\x4E': 'Animated Cursor (ANI)',
    b'\x42\x4C\x45\x4E\x44\x45\x52': 'Blender File',
    b'Kaydara FBX Binary  \x20': 'Autodesk FBX',
    b'4D4D': '3D Studio Mesh',
    b'\x73\x6C\x66\x34': 'SoundFont 2',
    b'\x56\x47\x4D\x20': 'Video Game Music (VGM)',
    b'\x50\x53\x49\x44': 'SID Music',
    b'\x52\x53\x49\x44': 'SID Music (RSID)',
}


SUSPICIOUS_MARKERS = {
    # Living-off-the-land interpreters / launchers
    b'powershell.exe': 'PowerShell EXE',
    b'powershell -': 'PowerShell Command',
    b'cmd /c ': 'CMD Command',
    b'wscript.exe': 'WScript',
    b'cscript.exe': 'CScript',
    b'mshta.exe': 'MSHTA',
    b'certutil -': 'CertUtil',
    b'regsvr32 ': 'Regsvr32',
    b'rundll32 ': 'RunDLL32',
    # Macro and script indicators
    b'autoopen()': 'Macro AutoOpen',
    b'auto_open()': 'Macro Auto_Open',
    b'workbook_open()': 'Macro Workbook_Open',
    b'wscript.shell': 'WScript.Shell',
    b'shell.application': 'Shell.Application',
    b'createobject(': 'CreateObject',
    b'vbscript:': 'VBScript',
    b'javascript:': 'JavaScript',
    b'eval(': 'Eval',
    b'executeglobal': 'ExecuteGlobal',
    # PowerShell obfuscation / evasion patterns
    b'-windowstyle hidden': 'Hidden Window',
    b'-windowstylehidden': 'Hidden Window',
    b'frombase64string': 'Base64 PowerShell',
    b'tochar(': 'Char Obfuscation',
    b'invoke-expression': 'Invoke-Expression',
    b'invoke-webrequest': 'Download',
    b'downloadstring': 'Download',
    b'downloadfile': 'Download',
    b'encodedcommand': 'Encoded Command',
    # Injection / process manipulation
    b'runpe': 'RunPE',
    b'process hollowing': 'Process Hollowing',
    b'virtualprotect': 'VirtualProtect',
    b'createremotethread': 'CreateRemoteThread',
    b'ntunmapviewofsection': 'NtUnmapViewOfSection',
    b'writeprocessmemory': 'WriteProcessMemory',
    b'rtlinject': 'APC/Thread Hijack',
    b'queueuserapc': 'APC Injection',
    b'setthreadcontext': 'Thread Context',
    b'resumethread': 'Resume Thread',
    b'shellcode': 'Shellcode',
    # Ransomware / wiper behavior
    b'delete shadows': 'Shadow Delete',
    b'vssadmin delete shadows': 'VSSAdmin Delete',
    b'bcdedit /set': 'BCDEdit',
    b'wevtutil cl': 'Log Wipe',
    b'cipher /w:': 'Cipher Wipe',
    # Malware family names
    b'wannacry': 'WannaCry',
    b'emotet': 'Emotet',
    b'trickbot': 'TrickBot',
    b'qakbot': 'QakBot',
    b'dridex': 'Dridex',
    b'locky': 'Locky',
    b'notpetya': 'NotPetya',
    b'cobaltstrike': 'Cobalt Strike',
    b'metasploit': 'Metasploit',
    b'mimikatz': 'Mimikatz',
    b'azorult': 'AZORult',
    b'lokibot': 'LokiBot',
    b'remcos': 'Remcos',
    b'nanocore': 'NanoCore',
    b'darkcomet': 'DarkComet',
    b'njrat': 'njRAT',
    b'revenge rat': 'Revenge RAT',
    b'information stealer': 'Stealer',
    b'infostealer': 'Stealer',
    # Evasion / anti-analysis
    b'amsi bypass': 'AMSI Bypass',
    b'amsi.fail': 'AMSI Bypass',
    b'etw bypass': 'ETW Bypass',
    b'patch amsi': 'AMSI Patch',
    b'patch etw': 'ETW Patch',
    b'blockdlls': 'Block DLLs',
    b'unhook': 'API Unhooking',
    b'sleep(': 'Evasive Sleep',
    b'sleepfor': 'Evasive Sleep',
    b'checkdebugger': 'Anti-Debug',
    b'isdebuggerpresent': 'Anti-Debug',
    b'outputdebugstring': 'Anti-Debug',
    b'vmware': 'Anti-VM',
    b'virtualbox': 'Anti-VM',
    b'sandbox': 'Anti-Sandbox',
    # Lateral movement / system abuse
    b'wmic process': 'WMIC Abuse',
    b'wmic /node': 'WMIC Lateral',
    b'wmic os': 'WMIC Recon',
    b'psexec': 'PsExec',
    b'schtasks /create': 'Scheduled Task',
    b'at\\': 'Scheduled Task',
    b'reg add': 'Registry Add',
    b'reg.exe add': 'Registry Add',
    b'netsh advfirewall': 'Firewall Change',
    b'netsh firewall set': 'Firewall Change',
    # Credential access
    b'lsass.exe': 'LSASS Access',
    b'lsadump': 'LSA Dump',
    b'sekurlsa': 'Mimikatz Sekurlsa',
    b'wdigest': 'WDigest',
    b'kerberos::ptt': 'Pass The Ticket',
    b'kerberos::ptc': 'Pass The Cache',
    b'kerberos::golden': 'Golden Ticket',
    b'kerberos::silver': 'Silver Ticket',
    b'tspkg': 'Credential Dump',
    b'logonpasswords': 'Password Dump',
    b'token::elevate': 'Token Elevation',
    b'token::impersonate': 'Token Impersonation',
    b'privilege::debug': 'Debug Privilege',
    b'sebackupprivilege': 'Backup Privilege',
    b'ntds.dit': 'NTDS Dump',
    b'sam': 'SAM Dump',
    b'vault::cred': 'Credential Vault',
    # C2 / exfil
    b'tor2web': 'Tor Proxy',
    b'.onion': 'Onion Domain',
    b'pastebin.com/raw': 'Pastebin Payload',
    b'githubusercontent.com': 'GitHub Payload',
    b'raw.githubusercontent': 'GitHub Payload',
    b'discord cdn': 'Discord CDN',
    b'telegram bot': 'Telegram C2',
    b'c2 ': 'C2 Reference',
    b'command and control': 'C2 Reference',
    b'exfil': 'Exfiltration',
    b'keylogger': 'Keylogger',
    b'keystrokes': 'Keylogger',
    b'capture screen': 'Screen Capture',
    b'webcam': 'Webcam Capture',
    b'microphone': 'Mic Capture',
    b'clipper': 'Clipboard Stealer',
    # UAC / token bypass
    b'uac bypass': 'UAC Bypass',
    b'eventvwr.exe': 'UAC Bypass',
    b'fodhelper.exe': 'UAC Bypass',
    b'computerdefaults.exe': 'UAC Bypass',
    b'adjusttokenprivileges': 'Privilege Escalation',
    b'lookupprivilegevalue': 'Privilege Escalation',
    # Reconnaissance / system commands
    b'ipconfig /all': 'Network Recon',
    b'ipconfig /flushdns': 'Network Recon',
    b'netstat -an': 'Network Recon',
    b'arp -a': 'Network Recon',
    b'route print': 'Network Recon',
    b'whoami': 'System Recon',
    b'whoami /all': 'System Recon',
    b'whoami /priv': 'Privilege Recon',
    b'systeminfo': 'System Recon',
    b'qwinsta': 'Session Recon',
    b'query user': 'Session Recon',
    b'query session': 'Session Recon',
    b'nltest': 'Domain Recon',
    b'nltest /domain_trusts': 'Domain Recon',
    b'nltest /dclist': 'Domain Recon',
    b'nltest /dsgetdc': 'Domain Recon',
    b'wmic qfe': 'Patch Recon',
    b'wmic process list': 'Process Recon',
    b'wmic useraccount': 'Account Recon',
    b'wmic computersystem': 'System Recon',
    b'wmic ntdomain': 'Domain Recon',
    b'wmic shadowcopy': 'Shadow Copy Recon',
    b'wmic /node:': 'Remote WMI',
    b'vssadmin list shadows': 'Shadow Copy Recon',
    b'wbadmin delete': 'Backup Delete',
    b'fsutil usn': 'USN Journal',
    b'bcdedit /set': 'Boot Config',
    b'bcdedit /delete': 'Boot Config',
    b'net user ': 'Account Manipulation',
    b'net localgroup ': 'Group Manipulation',
    b'net group ': 'Domain Group',
    b'net view ': 'Share Recon',
    b'net use ': 'Share Mount',
    b'net share ': 'Share Create',
    b'tasklist /v': 'Process Recon',
    b'taskkill /': 'Process Kill',
    # WMI / COM / Script abuse
    b'wmiexec': 'WMI Exec',
    b'wmic /output:': 'WMI Output',
    b'scripting.filesystemobject': 'Script Object',
    b'filesystemobject': 'Script Object',
    b'adodb.stream': 'ADODB Stream',
    b'adodb.connection': 'ADODB Connection',
    b'msxml2.xmlhttp': 'XMLHTTP',
    b'microsoft.xmlhttp': 'XMLHTTP',
    b'winhttp.winhttprequest.5.1': 'WinHTTP',
    b'winhttprequest': 'WinHTTP',
    b'scripting.dictionary': 'Script Dictionary',
    b'wscript.network': 'WScript Network',
    b'wscript.sleep': 'WScript Sleep',
    b'wscript.network': 'WScript Network',
    b'reg.read': 'Registry Read',
    b'reg.write': 'Registry Write',
    b'reg.delete': 'Registry Delete',
    b'reg.readall': 'Registry Read',
    # PowerShell features commonly abused
    b'new-object': 'New-Object',
    b'invoke-webrequest': 'Web Request',
    b'invoke-restmethod': 'REST Request',
    b'start-bitstransfer': 'BITS Transfer',
    b'net.webclient': 'WebClient',
    b'system.net.webclient': 'WebClient',
    b'downloadstring': 'Download',
    b'downloadfile': 'Download',
    b'downloaddata': 'Download',
    b'uploadstring': 'Upload',
    b'uploadfile': 'Upload',
    b'uploaddata': 'Upload',
    b'openread': 'Web Stream',
    b'openwrite': 'Web Stream',
    b'frombase64string': 'Base64 Decode',
    b'tobase64string': 'Base64 Encode',
    b'convert::frombase64string': 'Base64 Decode',
    b'convert::tobase64string': 'Base64 Encode',
    b'gzipstream': 'GZIP Stream',
    b'deflatestream': 'Deflate Stream',
    b'memorystream': 'Memory Stream',
    b'compress-archive': 'Archive',
    b'expand-archive': 'Archive',
    b'invoke-expression': 'Invoke Expression',
    b'invoke-item': 'Invoke Item',
    b'start-process': 'Start Process',
    b'get-process': 'Process Query',
    b'stop-process': 'Stop Process',
    b'set-executionpolicy': 'Execution Policy',
    b'executionpolicy bypass': 'Execution Policy',
    b'executionpolicy unrestricted': 'Execution Policy',
    b'erroraction silentlycontinue': 'Silence Errors',
    b'warningaction silentlycontinue': 'Silence Warnings',
    b'-noexit': 'No Exit',
    b'-encodedcommand': 'Encoded Command',
    b'-ep bypass': 'Execution Policy',
    b'-noprofile': 'No Profile',
    b'-noninteractive': 'Non-Interactive',
    # Crypto / wallet / mining
    b'xmrig': 'XMRig Miner',
    b'minerd': 'MinerD',
    b'cpuminer': 'CPU Miner',
    b'nicehash': 'NiceHash',
    b'minergate': 'MinerGate',
    b'stratum+tcp://': 'Mining Pool',
    b'stratum+ssl://': 'Mining Pool',
    b'stratum://': 'Mining Pool',
    b'nanopool': 'Mining Pool',
    b'supportxmr': 'Mining Pool',
    b'monerocean': 'Mining Pool',
    b'herominers': 'Mining Pool',
    b'xmrvsbeast': 'Mining Pool',
    b'xmr-stak': 'XMR Stak',
    b'claymore': 'Claymore Miner',
    b'phoenixminer': 'Phoenix Miner',
    b'coinminer': 'Coin Miner',
    b'wallet.dat': 'Wallet File',
    b'keystore': 'Crypto Keystore',
    # Browser / credential theft
    b'login data': 'Login Data',
    b'logindata': 'Login Data',
    b'web data': 'Web Data',
    b'cookies.sqlite': 'Firefox Cookies',
    b'cookies': 'Cookies',
    b'places.sqlite': 'Firefox History',
    b'key4.db': 'Firefox Key',
    b'cert9.db': 'Firefox Certs',
    b'signons.sqlite': 'Firefox Passwords',
    b'libnsecmodule.so': 'NSS Module',
    b'softoken': 'NSS Softoken',
    b'master password': 'Master Password',
    # Misc abuse patterns
    b'process doppelganging': 'Process Doppelganging',
    b'process hollowing': 'Process Hollowing',
    b'process ghosting': 'Process Ghosting',
    b'process herpaderping': 'Process Herpaderping',
    b'atom bombing': 'Atom Bombing',
    b'apc injection': 'APC Injection',
    b'thread hijack': 'Thread Hijack',
    b'manual map': 'Manual Map',
    b'dll hollowing': 'DLL Hollowing',
    b'reflective dll': 'Reflective DLL',
    b'reflectiveloader': 'Reflective Loader',
    b'peb walk': 'PEB Walk',
    b'ldrloaddll': 'LdrLoadDll',
    b'ntdll!': 'NTDLL Hook',
    b'kernel32!': 'Kernel32 Hook',
    b'wininet!': 'Wininet Hook',
    b'ws2_32!': 'Winsock Hook',
    b'httpapi!': 'HTTP Hook',
    b'cryptsp!': 'CryptoSP Hook',
    b'bcrypt!': 'BCrypt Hook',
    b'ncrypt!': 'NCrypt Hook',
    b'vaultcli!': 'Vault CLI',
}


def _read_registry_run_keys():
    """Read Windows Run and RunOnce keys for all users and the current user."""
    items = []
    keys = [
        (winreg.HKEY_CURRENT_USER, r'Software\Microsoft\Windows\CurrentVersion\Run'),
        (winreg.HKEY_CURRENT_USER, r'Software\Microsoft\Windows\CurrentVersion\RunOnce'),
        (winreg.HKEY_LOCAL_MACHINE, r'Software\Microsoft\Windows\CurrentVersion\Run'),
        (winreg.HKEY_LOCAL_MACHINE, r'Software\Microsoft\Windows\CurrentVersion\RunOnce'),
        (winreg.HKEY_LOCAL_MACHINE, r'Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'),
    ]
    for hkey, subkey in keys:
        try:
            with winreg.OpenKey(hkey, subkey, 0, winreg.KEY_READ) as key:
                i = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(key, i)
                        items.append({'source': 'Registry ' + subkey, 'name': name, 'command': str(value)})
                        i += 1
                    except OSError:
                        break
        except Exception:
            pass
    return items


def _read_startup_folders():
    """List files in the user and all-users startup folders."""
    items = []
    for base in (os.environ.get('APPDATA', ''), os.environ.get('PROGRAMDATA', '')):
        if not base:
            continue
        folder = os.path.join(base, 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup')
        if os.path.isdir(folder):
            for name in os.listdir(folder):
                path = os.path.join(folder, name)
                if os.path.isfile(path):
                    items.append({'source': 'Startup Folder', 'name': name, 'command': path})
    return items


def _read_scheduled_tasks():
    """Return a list of active scheduled tasks and their actions."""
    try:
        output = subprocess.check_output(
            ['schtasks', '/query', '/fo', 'csv', '/v'],
            shell=False,
            timeout=30,
            stderr=subprocess.STDOUT
        )
        text = output.decode('utf-8', errors='replace')
        lines = [l for l in text.splitlines() if l.strip()]
        if len(lines) < 2:
            return []
        headers = [h.strip().strip('"') for h in lines[0].split(',')]
        tasks = []
        for line in lines[1:]:
            fields = [f.strip().strip('"') for f in line.split(',')]
            if len(fields) < len(headers):
                continue
            row = dict(zip(headers, fields))
            if row.get('TaskName') and row.get('TaskName').strip():
                tasks.append({
                    'source': 'Scheduled Task',
                    'name': row.get('TaskName'),
                    'command': row.get('Task To Run', ''),
                    'status': row.get('Scheduled Task State', 'Unknown'),
                    'author': row.get('Author', ''),
                })
        return tasks[:200]
    except Exception as e:
        logging = __import__('logging')
        logging.getLogger('data_analysis').warning(f'Failed to query scheduled tasks: {e}')
        return []


def scan_startup_and_tasks():
    """Return a combined list of startup items, scheduled tasks, WMI and startup folders."""
    return _read_registry_run_keys() + _read_startup_folders() + _read_scheduled_tasks() + scan_wmi_subscriptions()


def _kill_switch_rule_name():
    return 'AntivirusServer_KillSwitch'


def is_kill_switch_active():
    """Check whether the kill-switch firewall rule exists."""
    try:
        output = subprocess.check_output(
            ['netsh', 'advfirewall', 'firewall', 'show', 'rule', 'name=' + _kill_switch_rule_name()],
            shell=False,
            timeout=10,
            stderr=subprocess.STDOUT
        )
        return _kill_switch_rule_name().encode() in output
    except Exception:
        return False


def enable_kill_switch():
    """Block all outbound network traffic with a Windows Firewall rule."""
    try:
        if is_kill_switch_active():
            return True, 'Kill switch already active'
        subprocess.check_call(
            ['netsh', 'advfirewall', 'firewall', 'add', 'rule',
             'name=' + _kill_switch_rule_name(), 'dir=out', 'action=block',
             'enable=yes', 'profile=any', 'remoteip=0.0.0.0-255.255.255.255'],
            shell=False,
            timeout=30
        )
        return True, 'Outbound traffic blocked'
    except Exception as e:
        return False, str(e)


def disable_kill_switch():
    """Remove the kill-switch firewall rule, restoring normal outbound traffic."""
    try:
        subprocess.check_call(
            ['netsh', 'advfirewall', 'firewall', 'delete', 'rule',
             'name=' + _kill_switch_rule_name()],
            shell=False,
            timeout=30
        )
        return True, 'Outbound traffic restored'
    except Exception as e:
        return False, str(e)


def _read_one_event_log(log_name, count=50, event_ids=None):
    """Read the most recent events from a Windows event log."""
    try:
        import win32evtlog
    except Exception:
        return [{'error': f'pywin32/win32evtlog not available for {log_name}'}]
    try:
        h = win32evtlog.OpenEventLog(None, log_name)
        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        events = []
        while len(events) < count:
            batch = win32evtlog.ReadEventLog(h, flags, 0)
            if not batch:
                break
            for ev in batch:
                if event_ids is None or (ev.EventID & 0xFFFF) in event_ids:
                    message = ev.StringInserts
                    if not message:
                        message = []
                    events.append({
                        'time': str(ev.TimeGenerated),
                        'id': ev.EventID & 0xFFFF,
                        'source': ev.SourceName,
                        'message': message[:8]
                    })
                if len(events) >= count:
                    break
        win32evtlog.CloseEventLog(h)
        return events[:count]
    except Exception as e:
        return [{'error': f'Failed to read {log_name}: {e}'}]


def read_security_events(count=50):
    """Read recent security events related to logons and process creation."""
    ids = {4624, 4625, 4648, 4672, 4688, 4697, 4720, 4724, 4738, 4740, 4768, 4769, 4771, 4776}
    return _read_one_event_log('Security', count=count, event_ids=ids)


def read_powershell_events(count=50):
    """Read recent Windows PowerShell/Operational events."""
    ids = {4103, 4104, 4105}
    return _read_one_event_log('Microsoft-Windows-PowerShell/Operational', count=count, event_ids=ids)


def read_defender_events(count=50):
    """Read recent Windows Defender detection events."""
    ids = {1116, 1117, 1118, 1119, 1120}
    return _read_one_event_log('Microsoft-Windows-Windows Defender/Operational', count=count, event_ids=ids)


def read_sysmon_events(count=50):
    """Read recent Sysmon process/network events if Sysmon is installed."""
    ids = {1, 3, 7, 22}
    return _read_one_event_log('Microsoft-Windows-Sysmon/Operational', count=count, event_ids=ids)


def read_recent_security_summary(count=50):
    """Return a summary of important Windows events across several logs."""
    return {
        'security': read_security_events(count),
        'powershell': read_powershell_events(count),
        'defender': read_defender_events(count),
        'sysmon': read_sysmon_events(count),
    }


SUSPICIOUS_EMAIL_ATTACHMENTS = {
    '.exe', '.scr', '.com', '.pif', '.bat', '.cmd', '.vbs', '.js', '.ps1',
    '.wsf', '.jar', '.iso', '.img'
}


def email_attachment_score(email_path):
    """Return a risk score (0-100) based on suspicious email attachments."""
    result = scan_email_attachments(email_path)
    if not result or not result.get('attachments'):
        return 0
    score = len(result.get('suspicious', [])) * 25
    # Double the score for any executable extension and penalise large attachment counts.
    for name in result.get('attachments', []):
        ext = os.path.splitext(name)[1].lower()
        if ext in {'.exe', '.scr', '.com', '.pif', '.jar'}:
            score += 20
    return min(100, score)


def startup_risk_score(item):
    """Score a startup/scheduled task item by its command string."""
    command = (item.get('command') or '').lower()
    score = 0
    if not command:
        return 0
    high_risk = [
        'powershell.exe', 'powershell ', 'cmd /c ', 'cmd.exe /c ',
        '-encodedcommand', '-enc ', 'frombase64string', 'base64',
        'vbscript:', 'javascript:', 'mshta.exe', 'regsvr32 ', 'rundll32 ',
        'certutil ', 'wscript.exe', 'cscript.exe',
        'vssadmin ', 'delete shadows', 'bcdedit ',
        'net user ', 'net localgroup ', 'taskkill ', 'sc ', 'schtasks ',
        'autorun', 'temp', '\\temp\\', '\\tmp\\',
        'appdata\\local\\', 'downloads\\', 'start-process ', 'iex ', 'invoke-expression'
    ]
    for marker in high_risk:
        if marker in command:
            score += 15
    if re.search(r'https?://', command):
        score += 20
    if re.search(r'[a-z0-9+/]{40,}={0,2}', command):
        score += 15
    return min(100, score)


def event_risk_score(event):
    """Score a Windows event by its ID and message contents."""
    score = 0
    eid = event.get('id')
    message = ' '.join(str(m) for m in event.get('message', [])).lower()
    if eid in {4625, 4771, 4776}:
        score += 10
    if eid in {4648, 4697, 7045}:
        score += 20
    if eid in {4688} and any(k in message for k in ['powershell', 'cmd', 'wscript', 'cscript', 'mshta', 'regsvr32', 'rundll32']):
        score += 25
    if eid in {4103, 4104}:
        score += 20
    if eid in {1116, 1117}:
        score += 50
    if eid in {1}:
        score += 15
    if eid in {22}:
        score += 25
    if 'hidden' in message or '-windowstyle hidden' in message:
        score += 15
    if 'encodedcommand' in message or 'frombase64string' in message:
        score += 20
    if re.search(r'https?://', message):
        score += 10
    score += credential_dump_score(message)
    return min(100, score)


def hash_lookup_risk_score(results):
    """Score a multi-engine hash lookup by total malicious hits."""
    score = 0
    for r in results:
        if r.get('source') == 'VirusTotal' and not r.get('error'):
            score += (r.get('malicious', 0) * 10) + (r.get('suspicious', 0) * 5)
        if r.get('source') == 'MalwareBazaar' and not r.get('error'):
            score += 40
        if r.get('source') == 'ThreatFox' and not r.get('error'):
            score += min(50, r.get('matches', 0) * 10)
    return min(100, score)


def scan_archive_file(file_path):
    """Inspect .zip and tar archives for suspicious file names."""
    result = {'files': [], 'suspicious': []}
    if not os.path.exists(file_path):
        return result
    ext = os.path.splitext(file_path)[1].lower()
    try:
        if ext == '.zip' or file_path.lower().endswith('.zip'):
            import zipfile
            with zipfile.ZipFile(file_path, 'r') as zf:
                result['files'] = zf.namelist()
        elif file_path.lower().endswith(('.tar', '.tar.gz', '.tgz')):
            import tarfile
            with tarfile.open(file_path, 'r:*') as tf:
                result['files'] = [m.name for m in tf.getmembers() if m.isfile()]
    except Exception:
        return result
    for name in result['files']:
        lower = name.lower()
        if os.path.splitext(name)[1].lower() in SUSPICIOUS_EMAIL_ATTACHMENTS:
            result['suspicious'].append(name)
        if lower.endswith('.lnk') or 'autorun' in lower or 'setup' in lower:
            result['suspicious'].append(name)
    return result


def scan_pdf_file(file_path):
    """Check a PDF for JavaScript / OpenAction / Launch keywords."""
    if not os.path.exists(file_path):
        return {'risky': False}
    try:
        with open(file_path, 'rb') as f:
            data = f.read(4 * 1024 * 1024)
        lowered = data.lower()
        found = []
        for marker in [b'/js', b'/javascript', b'/openaction', b'/launch', b'/submitform', b'/importdata']:
            if marker in lowered:
                found.append(marker.decode('latin-1', errors='replace'))
        return {'risky': bool(found), 'indicators': found}
    except Exception:
        return {'risky': False}


def scan_shortcut_file(file_path):
    """Basic .lnk risk check based on target commands it may execute."""
    if not os.path.exists(file_path):
        return {'risky': False}
    # Parse link target using a best-effort shell COM object if available.
    try:
        import win32com.client
        shell = win32com.client.Dispatch('WScript.Shell')
        shortcut = shell.CreateShortCut(file_path)
        target = (shortcut.Targetpath + ' ' + shortcut.Arguments).lower()
        score = 0
        for marker in ['powershell', 'cmd', '-enc', 'frombase64string', 'vbscript:', 'javascript:', 'regsvr32', 'rundll32', 'mshta', 'certutil', 'http']:
            if marker in target:
                score += 20
        return {'risky': score >= 20, 'score': min(100, score), 'target': target}
    except Exception:
        return {'risky': False}


def scan_macro_document(file_path):
    """Detect macro indicators in Office documents (.docm, .xlsm, .doc, .xls, .ppt)."""
    if not os.path.exists(file_path):
        return {'macro_risk': False}
    ext = os.path.splitext(file_path)[1].lower()
    if ext not in {'.docm', '.xlsm', '.pptm', '.dotm', '.xltm', '.doc', '.xls', '.ppt'}:
        return {'macro_risk': False}
    try:
        with open(file_path, 'rb') as f:
            data = f.read(2 * 1024 * 1024)
        lowered = data.lower()
        indicators = []
        for marker in [b'vba', b'macros', b'autoopen', b'autopen', b'auto_open', b'document_open', b'workbook_open', b'project', b'thisdocument']:
            if marker in lowered:
                indicators.append(marker.decode('latin-1', errors='replace'))
        return {'macro_risk': bool(indicators), 'indicators': indicators}
    except Exception:
        return {'macro_risk': False}


POWERSHELL_SUSPICIOUS_PATTERNS = [
    ('encodedcommand', 25),
    ('-enc ', 20),
    ('-ep bypass', 20),
    ('-executionpolicy bypass', 20),
    ('frombase64string', 25),
    ('iex ', 15),
    ('invoke-expression', 20),
    ('invoke-webrequest', 20),
    ('wget ', 15),
    ('net.webclient', 15),
    ('downloadstring', 20),
    ('downloadfile', 20),
    ('start-process', 10),
    ('new-object', 10),
    ('system.net.webclient', 20),
    ('powershell.exe -', 10),
    ('vbscript:', 25),
    ('javascript:', 25),
    ('win32_process', 15),
    ('create', 5),
    ('-windowstyle hidden', 20),
    ('-windowstylehidden', 20),
    ('[convert]::frombase64string', 25),
    ('-sta', 5),
    ('-nop', 10),
    # UAC bypass helpers
    ('fodhelper', 25),
    ('computerdefaults', 25),
    ('sdclt', 25),
    ('silentcleanup', 25),
    ('slui', 25),
    # Shadow-copy deletion / recovery tampering
    ('vssadmin delete shadows', 30),
    ('vssadmin delete', 25),
    ('wbadmin delete catalog', 30),
    ('bcdedit', 20),
    ('wevtutil cl', 20),
    # COM / DLL / process injection
    ('comsvcs', 25),
    ('minidump', 25),
    ('openprocess', 20),
    ('virtualalloc', 20),
    ('writeprocessmemory', 20),
    ('createremotethread', 20),
    ('queueuserapc', 20),
    ('setthreadcontext', 20),
    ('ntunmapviewofsection', 20),
    ('loadlibrary', 15),
    ('reg.exe add', 15),
    ('hklm\\software\\classes\\', 15),
]


def _decode_base64_powershell(text):
    """Try to find and decode base64-looking strings inside PowerShell text."""
    decoded = []
    import base64
    # Look for base64 strings of at least 40 characters.
    for match in re.finditer(r'[A-Za-z0-9+/]{40,}={0,2}', text):
        b64 = match.group(0)
        try:
            raw = base64.b64decode(b64)
            # Keep only printable/ascii strings
            candidate = raw.decode('utf-16-le', errors='replace')
            if len(candidate) > 5:
                decoded.append(candidate)
                continue
        except Exception:
            pass
        try:
            candidate = raw.decode('utf-8', errors='replace')
            if len(candidate) > 5:
                decoded.append(candidate)
        except Exception:
            pass
    return decoded


def scan_powershell_script_block(event):
    """Score a PowerShell event for malicious script patterns and decode base64."""
    message = ' '.join(str(m) for m in event.get('message', []))
    lowered = message.lower()
    score = 0
    indicators = []
    for pattern, weight in POWERSHELL_SUSPICIOUS_PATTERNS:
        if pattern in lowered:
            score += weight
            indicators.append(pattern)
    decoded = _decode_base64_powershell(message)
    for d in decoded:
        dlower = d.lower()
        for pattern, weight in POWERSHELL_SUSPICIOUS_PATTERNS:
            if pattern in dlower:
                score += weight
                if pattern not in indicators:
                    indicators.append(pattern)
    # Penalise very large encoded blocks.
    if len(decoded) > 2:
        score += 15
    return {
        'score': min(100, score),
        'indicators': list(set(indicators))[:20],
        'decoded_blocks': decoded[:5],
    }


def scan_wmi_subscriptions():
    """Detect WMI event subscription persistence entries."""
    try:
        output = subprocess.check_output(
            [
                'powershell', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command',
                'Get-CimInstance -ClassName __EventFilter -Namespace root/subscription | '
                'Select-Object Name, Query, __CLASS | ConvertTo-Json -Compress'
            ],
            shell=False,
            timeout=20,
            stderr=subprocess.STDOUT
        )
        text = output.decode('utf-8', errors='replace')
        data = json.loads(text) if text.strip() else []
        if isinstance(data, dict):
            data = [data]
        items = []
        for d in data:
            if not d:
                continue
            name = d.get('Name') or d.get('name') or 'WMI EventFilter'
            query = d.get('Query') or d.get('query') or ''
            items.append({
                'source': 'WMI Event Subscription',
                'name': name,
                'command': query,
                'status': d.get('__CLASS') or '',
                'author': 'WMI'
            })
        return items
    except Exception:
        return []


CREDENTIAL_DUMPING_PATTERNS = [
    ('sekurlsa', 30),
    ('wdigest', 25),
    ('mimikatz', 35),
    ('procdump', 25),
    ('lsass', 20),
    ('dump::', 30),
    ('token::elevate', 25),
    ('privilege::debug', 25),
    ('kerberos::', 25),
    ('process::create', 20),
    ('lsadump::', 30),
    ('vault::', 20),
    ('dpapi::', 20),
    ('crypto::', 20),
    ('rdrleakdiag', 20),
    ('comsvcs', 25),
    ('minidump', 20),
]


def credential_dump_score(text):
    """Score a string for credential-dumping tool usage."""
    if not text:
        return 0
    lowered = text.lower()
    score = 0
    for pattern, weight in CREDENTIAL_DUMPING_PATTERNS:
        if pattern in lowered:
            score += weight
    return min(100, score)


CANARY_CONTENT = 'CANARY_FILE_DO_NOT_MODIFY_OR_DELETE'
CANARY_FOLDERS = ['Desktop', 'Documents', 'Downloads', 'Pictures']


def _canary_dir():
    runtime = os.environ.get('ANTIVIRUS_RUNTIME_DIR', os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(runtime, 'canary')


def create_canary_files():
    """Create canary files in user folders for ransomware detection."""
    user = os.environ.get('USERPROFILE', os.path.expanduser('~'))
    state = {}
    for folder in CANARY_FOLDERS:
        target_dir = os.path.join(user, folder)
        if not os.path.isdir(target_dir):
            continue
        path = os.path.join(target_dir, 'canary_readme.txt')
        try:
            with open(path, 'w', encoding='utf-8') as f:
                f.write(CANARY_CONTENT)
            h = hashlib.sha256(CANARY_CONTENT.encode()).hexdigest()
            state[path] = h
        except Exception:
            pass
    os.makedirs(_canary_dir(), exist_ok=True)
    with open(os.path.join(_canary_dir(), 'canary_state.json'), 'w', encoding='utf-8') as f:
        json.dump(state, f)
    return state


def check_canary_files():
    """Check whether canary files were modified, deleted or renamed."""
    state_path = os.path.join(_canary_dir(), 'canary_state.json')
    if not os.path.exists(state_path):
        return []
    try:
        with open(state_path, 'r', encoding='utf-8') as f:
            expected = json.load(f)
    except Exception:
        return []
    results = []
    for path, expected_hash in expected.items():
        status = 'ok'
        if not os.path.exists(path):
            status = 'missing'
        else:
            try:
                with open(path, 'rb') as f:
                    data = f.read()
                current_hash = hashlib.sha256(data).hexdigest()
                if current_hash != expected_hash:
                    status = 'modified'
            except Exception:
                status = 'inaccessible'
        results.append({'path': path, 'status': status})
    return results


def scan_network_connections():
    """Return a list of current network connections with risk scoring."""
    try:
        import psutil
    except Exception:
        return []
    connections = []
    for c in psutil.net_connections(kind='inet'):
        try:
            if c.status not in ('ESTABLISHED', 'LISTEN'):
                continue
            laddr = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else ''
            raddr = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else ''
            connections.append({
                'pid': c.pid,
                'status': c.status,
                'local': laddr,
                'remote': raddr,
            })
        except Exception:
            continue
    return connections


def network_beacon_score(conn, iocs=None):
    """Score a network connection for suspicious remote addresses."""
    if iocs is None:
        iocs = _load_iocs()
    score = 0
    remote = (conn.get('remote') or '').lower()
    if not remote:
        return 0
    # High port / non-standard.
    try:
        port = int(remote.split(':')[-1])
        if port not in {80, 443, 53, 123, 20, 21, 22, 25, 110, 143, 993, 995, 587, 993, 3389}:
            score += 5
        if port in {4444, 5555, 6666, 7777, 8888, 31337, 12345}:
            score += 25
    except Exception:
        pass
    # DGA-like high-entropy domain.
    domain_part = remote.split(':')[0]
    if '.' in domain_part and not domain_part.replace('.', '').isdigit():
        labels = domain_part.split('.')
        for label in labels:
            if len(label) >= 16:
                score += 20
            if re.search(r'[0-9a-f]{20}', label):
                score += 15
    # IOC matches.
    for ip in iocs.get('ips', []):
        if ip.lower() in remote:
            score += 30
    for domain in iocs.get('domains', []):
        if domain.lower() in remote:
            score += 25
    for url in iocs.get('urls', []):
        if url.lower() in remote:
            score += 25
    return min(100, score)


STARTUP_REGISTRY_KEY = r'Software\Microsoft\Windows\CurrentVersion\Run'
STARTUP_APP_VALUE = 'AntivirusServer'


def update_ioc_feeds():
    """Download recent IOCs from URLhaus and ThreatFox and merge them into iocs.json."""
    import requests
    runtime = os.environ.get('ANTIVIRUS_RUNTIME_DIR', os.path.dirname(os.path.abspath(__file__)))
    ioc_path = os.path.join(runtime, 'iocs.json')
    try:
        with open(ioc_path, 'r', encoding='utf-8') as f:
            iocs = json.load(f)
    except Exception:
        iocs = DEFAULT_IOCS
    if not isinstance(iocs, dict):
        iocs = DEFAULT_IOCS
    # URLhaus recent URLs
    try:
        r = requests.get('https://urlhaus-api.abuse.ch/v1/urls/recent/', timeout=20)
        if r.status_code == 200:
            data = r.json()
            for u in data.get('urls', []):
                url = u.get('url')
                if url and url not in iocs['urls']:
                    iocs['urls'].append(url)
                ip = u.get('url_status_ip') or u.get('reporter_ip')
                if ip and ip not in iocs['ips']:
                    iocs['ips'].append(ip)
    except Exception as e:
        logging.getLogger('data_analysis').warning(f'URLhaus update failed: {e}')
    # ThreatFox recent IOCs
    try:
        r = requests.post('https://threatfox-api.abuse.ch/api/v1/', json={'query': 'get_iocs', 'days': 1}, timeout=20)
        if r.status_code == 200:
            data = r.json()
            for ioc in data.get('data', []):
                ioc_value = ioc.get('ioc')
                ioc_type = ioc.get('ioc_type')
                if not ioc_value:
                    continue
                if ioc_type in ('ip:port_ip', 'ip'):
                    if ioc_value not in iocs['ips']:
                        iocs['ips'].append(ioc_value)
                elif ioc_type == 'domain':
                    if ioc_value not in iocs['domains']:
                        iocs['domains'].append(ioc_value)
                elif ioc_type == 'url':
                    if ioc_value not in iocs['urls']:
                        iocs['urls'].append(ioc_value)
    except Exception as e:
        logging.getLogger('data_analysis').warning(f'ThreatFox update failed: {e}')
    # Trim to avoid unbounded growth
    iocs['ips'] = iocs['ips'][-5000:]
    iocs['domains'] = iocs['domains'][-5000:]
    iocs['urls'] = iocs['urls'][-5000:]
    try:
        with open(ioc_path, 'w', encoding='utf-8') as f:
            json.dump(iocs, f, indent=2)
    except Exception as e:
        logging.getLogger('data_analysis').warning(f'Failed to write iocs.json: {e}')
        return False
    return True


def is_startup_enabled():
    """Check whether the app is set to start with Windows for the current user."""
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, STARTUP_REGISTRY_KEY, 0, winreg.KEY_READ) as key:
            winreg.QueryValueEx(key, STARTUP_APP_VALUE)
            return True
    except Exception:
        return False


def toggle_startup_with_windows(enable):
    """Add or remove the app from the current user's Run key."""
    try:
        if enable:
            import sys
            exe_path = sys.executable
            if exe_path.endswith('pythonw.exe') or exe_path.endswith('python.exe'):
                exe_path = os.path.join(os.path.dirname(exe_path), 'AntivirusServer.exe')
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, STARTUP_REGISTRY_KEY, 0, winreg.KEY_SET_VALUE) as key:
                winreg.SetValueEx(key, STARTUP_APP_VALUE, 0, winreg.REG_SZ, f'"{exe_path}"')
            return True
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, STARTUP_REGISTRY_KEY, 0, winreg.KEY_SET_VALUE) as key:
            winreg.DeleteValue(key, STARTUP_APP_VALUE)
            return True
    except Exception as e:
        logging.getLogger('data_analysis').warning(f'Startup toggle failed: {e}')
        return False


def scan_windows_services():
    """Return a list of Windows services with their display name and start type."""
    try:
        import psutil
    except Exception:
        return []
    services = []
    for s in psutil.win_service_iter():
        try:
            d = s.as_dict()
            services.append({
                'name': d.get('name', ''),
                'display_name': d.get('display_name', ''),
                'status': d.get('status', ''),
                'start_type': d.get('start_type', ''),
                'binpath': d.get('binpath', '')
            })
        except Exception:
            continue
    return services


def service_risk_score(svc):
    """Score a Windows service for suspicious paths or names."""
    name = (svc.get('name') or '').lower()
    display = (svc.get('display_name') or '').lower()
    binpath = (svc.get('binpath') or '').lower()
    text = name + ' ' + display + ' ' + binpath
    score = 0
    suspicious = [
        'powershell', 'cmd', 'wscript', 'cscript', 'mshta', 'regsvr32',
        'rundll32', 'certutil', 'bitsadmin', 'msbuild', 'installutil',
        '-enc ', 'frombase64string', 'http', 'https', '.bat', '.cmd', '.vbs', '.ps1',
        '\\temp\\', '\\tmp\\', '\\appdata\\local\\', '\\users\\public\\',
        '\\windows\\temp\\'
    ]
    for marker in suspicious:
        if marker in text:
            score += 15
    if 'auto' in (svc.get('start_type') or '').lower() and ('\\temp\\' in binpath or '\\users\\' in binpath or '\\downloads\\' in binpath):
        score += 25
    return min(100, score)


def scan_running_processes():
    """Return a list of running Windows processes with basic metadata."""
    try:
        import psutil
    except Exception:
        return []
    processes = []
    for p in psutil.process_iter(['pid', 'name', 'ppid', 'exe', 'cmdline', 'username']):
        try:
            info = p.info
            cmdline = ' '.join(info.get('cmdline') or []) if info.get('cmdline') else ''
            processes.append({
                'pid': info.get('pid'),
                'ppid': info.get('ppid'),
                'name': info.get('name', ''),
                'exe': info.get('exe', ''),
                'cmdline': cmdline,
                'username': info.get('username', '')
            })
        except Exception:
            continue
    return processes


def process_risk_score(proc):
    """Score a running process for suspicious injection / LOLBAS / parent anomalies."""
    score = 0
    name = (proc.get('name') or '').lower()
    exe = (proc.get('exe') or '').lower()
    cmd = (proc.get('cmdline') or '').lower()
    parent = proc.get('ppid')

    if not name and not exe:
        return 0

    # Process image name does not match executable on disk.
    if name and exe and not exe.endswith(name):
        score += 20

    suspicious = [
        'powershell', 'cmd', 'wscript', 'cscript', 'mshta', 'regsvr32',
        'rundll32', 'certutil', 'bitsadmin', 'msbuild', 'installutil',
        'frombase64string', '-enc ', 'encodedcommand', 'invoke-expression',
        'iex ', 'downloadstring', 'downloadfile', 'net.webclient',
        'createremotethread', 'queueuserapc', 'setthreadcontext',
        'ntunmapviewofsection', 'process hollowing', 'virtualallocex',
        'writeprocessmemory', 'loadlibrary', 'apc inject',
        'vssadmin ', 'delete shadows', 'bcdedit ', 'wevtutil ', 'fsutil ',
        'net user ', 'net localgroup ', 'taskkill ', 'reg ', 'schtasks ',
        'fodhelper', 'computerdefaults', 'sdclt', 'silentcleanup', 'slui',
        'wbadmin delete', 'wevtutil cl', 'comsvcs', 'minidump',
        'openprocess', 'virtualalloc', 'reg.exe add', 'hklm\\software\\classes\\',
        ' -ep bypass', ' -executionpolicy bypass'
    ]
    for marker in suspicious:
        if marker in cmd or marker in exe:
            score += 10
    if re.search(r'-?[a-z0-9+/]{40,}={0,2}', cmd):
        score += 15

    # Parent/child anomalies.
    office_apps = ['winword.exe', 'excel.exe', 'powerpnt.exe', 'outlook.exe']
    if name in ['cmd.exe', 'powershell.exe', 'wscript.exe', 'cscript.exe']:
        # More suspicious if the child is an interpreter and parent is likely Office.
        try:
            import psutil
            parent_proc = psutil.Process(parent) if parent else None
            parent_name = parent_proc.name().lower() if parent_proc else ''
            if parent_name in office_apps:
                score += 30
            if parent_name in ['winlogon.exe', 'lsass.exe', 'services.exe']:
                score += 40
        except Exception:
            pass
    if name in office_apps:
        if 'http' in cmd or 'https' in cmd:
            score += 25

    # Unusual paths: processes running from temp, downloads, appdata local.
    bad_paths = ['\\temp\\', '\\tmp\\', '\\downloads\\', '\\appdata\\local\\', '\\users\\public\\']
    for bp in bad_paths:
        if bp in exe or bp in cmd:
            score += 20

    score += credential_dump_score(cmd + ' ' + name + ' ' + exe)
    return min(100, score)


def extra_file_risk_score(file_path):
    """Combine archive, PDF, shortcut and macro checks into one 0-100 risk score."""
    score = 0
    ext = os.path.splitext(file_path)[1].lower()
    if ext in {'.zip', '.tar', '.tgz', '.tar.gz'}:
        archive = scan_archive_file(file_path)
        if archive.get('suspicious'):
            score += min(80, len(archive['suspicious']) * 25)
    if ext == '.pdf':
        pdf = scan_pdf_file(file_path)
        if pdf.get('risky'):
            score += 30
    if ext == '.lnk':
        lnk = scan_shortcut_file(file_path)
        if lnk.get('risky'):
            score += lnk.get('score', 30)
    if ext in {'.docm', '.xlsm', '.pptm', '.dotm', '.xltm', '.doc', '.xls', '.ppt'}:
        macro = scan_macro_document(file_path)
        if macro.get('macro_risk'):
            score += 40
    return min(100, score)


def scan_email_attachments(file_path):
    """Extract attachment names from an .eml/.msg file and flag suspicious ones."""
    result = {'attachments': [], 'suspicious': []}
    if not os.path.exists(file_path):
        return result
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
        if data.lstrip().startswith(b'From:'):
            import email
            msg = email.message_from_bytes(data)
            for part in msg.walk():
                if part.get_content_maintype() == 'multipart':
                    continue
                filename = part.get_filename()
                if filename:
                    result['attachments'].append(filename)
                    if os.path.splitext(filename)[1].lower() in SUSPICIOUS_EMAIL_ATTACHMENTS:
                        result['suspicious'].append(filename)
        else:
            try:
                import extract_msg
                msg = extract_msg.Message(file_path)
                for att in msg.attachments:
                    name = att.longFilename or att.shortFilename or 'unnamed'
                    result['attachments'].append(name)
                    if os.path.splitext(name)[1].lower() in SUSPICIOUS_EMAIL_ATTACHMENTS:
                        result['suspicious'].append(name)
            except Exception:
                pass
    except Exception:
        pass
    return result


def multi_engine_hash_lookup(sha256):
    """Query VirusTotal, MalwareBazaar and ThreatFox for a SHA-256 hash."""
    import requests
    results = []
    if not sha256 or len(sha256) != 64:
        return results

    # VirusTotal
    vt_key = os.environ.get('VT_API_KEY', '').strip()
    if vt_key:
        try:
            r = requests.get(
                f'https://www.virustotal.com/api/v3/files/{sha256}',
                headers={'x-apikey': vt_key},
                timeout=20
            )
            if r.status_code == 200:
                data = r.json()
                attr = data.get('data', {}).get('attributes', {})
                stats = attr.get('last_analysis_stats', {})
                results.append({
                    'source': 'VirusTotal',
                    'url': f'https://www.virustotal.com/gui/file/{sha256}',
                    'malicious': stats.get('malicious', 0),
                    'suspicious': stats.get('suspicious', 0),
                    'harmless': stats.get('harmless', 0),
                    'undetected': stats.get('undetected', 0),
                    'raw': data
                })
            else:
                results.append({'source': 'VirusTotal', 'error': f'HTTP {r.status_code}'})
        except Exception as e:
            results.append({'source': 'VirusTotal', 'error': str(e)})
    else:
        results.append({'source': 'VirusTotal', 'error': 'VT_API_KEY not configured'})

    # MalwareBazaar
    try:
        r = requests.post(
            'https://mb-api.abuse.ch/api/v1/',
            data={'query': 'get_info', 'hash': sha256},
            timeout=20
        )
        if r.status_code == 200:
            data = r.json()
            if data.get('query_status') == 'ok' and data.get('data'):
                sample = data['data'][0]
                results.append({
                    'source': 'MalwareBazaar',
                    'url': f'https://bazaar.abuse.ch/sample/{sha256}/',
                    'malicious': 1,
                    'signature': sample.get('signature', ''),
                    'tags': sample.get('tags', []),
                    'raw': data
                })
            else:
                results.append({'source': 'MalwareBazaar', 'error': 'Not found'})
        else:
            results.append({'source': 'MalwareBazaar', 'error': f'HTTP {r.status_code}'})
    except Exception as e:
        results.append({'source': 'MalwareBazaar', 'error': str(e)})

    # ThreatFox
    try:
        r = requests.post(
            'https://threatfox-api.abuse.ch/api/v1/',
            json={'query': 'search_ioc', 'search_term': sha256},
            timeout=20
        )
        if r.status_code == 200:
            data = r.json()
            if data.get('query_status') == 'ok' and data.get('data'):
                results.append({
                    'source': 'ThreatFox',
                    'url': 'https://threatfox.abuse.ch/browse.php?search=ioc%3A' + sha256,
                    'matches': len(data['data']),
                    'raw': data
                })
            else:
                results.append({'source': 'ThreatFox', 'error': 'Not found'})
        else:
            results.append({'source': 'ThreatFox', 'error': f'HTTP {r.status_code}'})
    except Exception as e:
        results.append({'source': 'ThreatFox', 'error': str(e)})

    return results

def detect_file_signature(file_path, sample=1024):
    """Read the start of a file and return a friendly file type label."""
    if not os.path.exists(file_path):
        return 'Missing'
    try:
        with open(file_path, 'rb') as f:
            data = f.read(sample)
    except Exception:
        return 'Unreadable'
    for sig, label in FILE_SIGNATURES.items():
        if data.startswith(sig):
            return label
    if not data:
        return 'Empty'
    # Check for suspicious / malware-like markers anywhere in the sample
    lowered = data.lower()
    for marker, label in SUSPICIOUS_MARKERS.items():
        if marker in lowered:
            return 'Suspicious: ' + label
    # Heuristic text vs binary
    try:
        data[:sample].decode('utf-8')
        return 'Text/Unknown'
    except UnicodeDecodeError:
        return 'Binary/Unknown'


def generate_threat_graph(entries, output_path):
    """Generate a bar chart of the top risky file hashes/entries.

    entries: list of dicts with 'label', 'risk' and optional 'entropy'/'ml'.
    output_path: where to save the PNG.
    """
    if not entries:
        return False
    try:
        import matplotlib
        matplotlib.use('Agg')
        import matplotlib.pyplot as plt
        labels = [e['label'][:16] for e in entries]
        risks = [e['risk'] for e in entries]
        plt.figure(figsize=(10, 5))
        plt.bar(labels, risks, color='crimson')
        plt.title('Top Files by Risk Score')
        plt.xlabel('File Hash / Path')
        plt.ylabel('Risk Score')
        plt.xticks(rotation=45, ha='right')
        plt.tight_layout()
        os.makedirs(os.path.dirname(output_path) or '.', exist_ok=True)
        plt.savefig(output_path)
        plt.close()
        return True
    except Exception as e:
        print(f'Failed to generate threat graph: {e}')
        return False


if __name__ == "__main__":
    # Call the analyze_data function
    analyze_data(data)