# checks.py

def is_external(ip):
    """
    Vérifie si l'IP est externe (חיצונית).
    Une IP est interne si elle commence par '192.168' ou '10'.
    """
    #
    return not (ip.startswith("192.168") or ip.startswith("10."))

def is_sensitive_port(port):
    """
    Vérifie si le port est considéré comme sensible (פורט רגיש).
    """
    # Ports définis dans ton cours : 22 (SSH), 23 (Telnet), 3389 (RDP)
    sensitive_ports = ["22", "23", "3389"]
    return str(port) in sensitive_ports

def is_large_packet(size):
    """
    Vérifie si la taille du paquet est inhabituelle (גודל חריג).
    """
    # Seuil fixé à 5000 octets
    return int(size) > 5000

