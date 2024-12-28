import pandas as pd
import joblib
import re
import math


def calculate_entropy(text):
    """Calculate Shannon entropy of text"""
    if not text or not isinstance(text, str):
        return 0
    entropy = 0
    for x in range(256):
        p_x = float(text.count(chr(x))) / len(text)
        if p_x > 0:
            entropy += - p_x * math.log(p_x, 2)
    return entropy


def calculate_dns_tunneling_features(dns_info):
    """Calculate DNS tunneling-specific features"""
    if not isinstance(dns_info, str):
        return {
            'subdomain_length': 0,
            'unique_chars': 0,
            'digit_ratio': 0,
            'entropy': 0
        }

    # Calculate subdomain length
    subdomains = dns_info.split('.') if dns_info else []
    subdomain_length = max([len(sub) for sub in subdomains]) if subdomains else 0

    # Calculate unique characters ratio
    unique_chars = len(set(dns_info)) / len(dns_info) if dns_info else 0

    # Calculate digit ratio
    digit_count = sum(c.isdigit() for c in dns_info)
    digit_ratio = digit_count / len(dns_info) if dns_info else 0

    # Calculate entropy
    entropy = calculate_entropy(dns_info)

    return {
        'subdomain_length': subdomain_length,
        'unique_chars': unique_chars,
        'digit_ratio': digit_ratio,
        'entropy': entropy
    }


def parse_dns_packet(packet):
    """
    Parse DNS packet and extract relevant features.

    Args:
        packet (str): Raw DNS packet data.

    Returns:
        dict: Parsed data with additional tunneling features.
    """
    # Basic packet parsing
    timestamp = packet.split(' ')[0]

    # Source IP and Port
    ip_port_pattern = r"(\d+\.\d+\.\d+\.\d+)\.(\d+)"
    ip_port_match = re.search(ip_port_pattern, packet)
    source_ip = ip_port_match.group(1) if ip_port_match else None
    source_port = ip_port_match.group(2) if ip_port_match else None

    # Target Domain
    target_domain = re.search(r"> (.*?)\:", packet)
    target_domain = target_domain.group(1) if target_domain else None

    # DNS Type
    dns_type = re.search(r" (\w+)[\s\?]", packet)
    dns_type = dns_type.group(1) if dns_type else None

    # DNS Query
    dns_query = re.search(r"\? (.*?)[\.\s]", packet)
    dns_query = dns_query.group(1) if dns_query else None

    # Response Length
    response_length = re.search(r"\((\d+)\)", packet)
    response_length = int(response_length.group(1)) if response_length else 0

    # Calculate tunneling features
    tunneling_features = calculate_dns_tunneling_features(dns_query)

    # Combine all features
    dns_data = {
        "ZamanDamgasi": timestamp,
        "Kaynak_IP": source_ip,
        "Kaynak_Port": source_port,
        "Hedef_Domain": target_domain,
        "DNS_Turu": dns_type,
        "DNS_Bilgisi": dns_query,
        "DNS_CevapUzunlugu": response_length,
        "subdomain_length": tunneling_features['subdomain_length'],
        "unique_chars_ratio": tunneling_features['unique_chars'],
        "digit_ratio": tunneling_features['digit_ratio'],
        "query_entropy": tunneling_features['entropy']
    }

    return dns_data


def prepare_data_for_prediction(dns_data):
    """
    Prepare DNS data for model prediction.

    Args:
        dns_data (dict): Extracted DNS data.

    Returns:
        DataFrame: Processed data ready for model prediction.
    """
    try:
        # Load model and scaler
        model = joblib.load('dns_tunnel_model.joblib')
        scaler = joblib.load('dns_tunnel_scaler.joblib')
    except FileNotFoundError:
        raise FileNotFoundError("Model or scaler files not found. Please ensure the model is trained first.")

    # Create DataFrame with tunneling features
    feature_columns = [
        'DNS_CevapUzunlugu',
        'subdomain_length',
        'unique_chars_ratio',
        'digit_ratio',
        'query_entropy'
    ]

    dns_df = pd.DataFrame([{
        'DNS_CevapUzunlugu': dns_data['DNS_CevapUzunlugu'],
        'subdomain_length': dns_data['subdomain_length'],
        'unique_chars_ratio': dns_data['unique_chars_ratio'],
        'digit_ratio': dns_data['digit_ratio'],
        'query_entropy': dns_data['query_entropy']
    }])

    # Scale features
    dns_df_scaled = pd.DataFrame(
        scaler.transform(dns_df),
        columns=feature_columns
    )

    return dns_df_scaled


def predict_dns_tunnel(packet):
    """
    Predict whether a DNS packet contains tunneling.

    Args:
        packet (str): Raw DNS packet data.

    Returns:
        dict: Prediction result with confidence score.
    """
    try:
        # Load model
        model = joblib.load('dns_tunnel_model.joblib')
    except FileNotFoundError:
        raise FileNotFoundError("Model file not found. Please ensure the model is trained first.")

    # Parse and prepare data
    dns_data = parse_dns_packet(packet)
    dns_df_prepared = prepare_data_for_prediction(dns_data)

    # Make prediction
    prediction = model.predict(dns_df_prepared)[0]
    probabilities = model.predict_proba(dns_df_prepared)[0]
    confidence = max(probabilities)

    result = {
        'prediction': 'DNS Tüneli Algılandı' if prediction == 'Tunnel' else 'DNS Tüneli Algılanmadı',
        'confidence': f'{confidence:.2%}',
        'features': {
            'subdomain_length': dns_data['subdomain_length'],
            'unique_chars_ratio': f'{dns_data["unique_chars_ratio"]:.3f}',
            'digit_ratio': f'{dns_data["digit_ratio"]:.3f}',
            'entropy': f'{dns_data["query_entropy"]:.3f}'
        }
    }

    return result


if __name__ == "__main__":
    # Test packet
    test_packets = [
        "15:22:33.123456 IP 192.168.1.100.53531 > dns.attacker.com: A? data.4d6f73744c696b656c79546f42655475.tunnel.evil.com. (128)"
    ]

    print("DNS Packet Analysis Results:")
    print("-" * 50)

    for i, packet in enumerate(test_packets, 1):
        try:
            result = predict_dns_tunnel(packet)
            print(f"\nPacket {i}:")
            print(f"Raw packet: {packet}")
            print(f"Prediction: {result['prediction']}")
            print(f"Confidence: {result['confidence']}")
            print("\nFeature Analysis:")
            for feature, value in result['features'].items():
                print(f"- {feature}: {value}")
            print("-" * 50)
        except Exception as e:
            print(f"Error analyzing packet {i}: {str(e)}")