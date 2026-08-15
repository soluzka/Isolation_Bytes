from collections import Counter
import math
import os
from cryptography.fernet import Fernet

# Visualization imports
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