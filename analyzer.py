from checks import is_external, is_sensitive_port, is_large_packet


def analyze_traffic(data):
    """
    Analyse les 10 000 lignes et crée un dictionnaire des suspects.
    Le but est de mapper chaque IP à ses comportements suspects.
    """
    suspicious_report = {}

    for line in data:
        # On extrait les infos selon la structure : timestamp, src_ip, dest_ip, port, protocol, size
        source_ip = line[1]
        port = line[3]
        size = line[5]

        # Liste pour stocker les raisons de suspicion pour cette ligne précise
        reasons = []

        # 1. Test IP Externe
        if is_external(source_ip):
            reasons.append("EXTERNAL_IP")

        # 2. Test Port Sensible
        if is_sensitive_port(port):
            reasons.append("SENSITIVE_PORT")

        # 3. Test Taille (Large Packet)
        if is_large_packet(size):
            reasons.append("LARGE_PACKET")

        # Si on a trouvé des raisons suspectes (la liste n'est pas vide)
        if reasons:
            # Si l'IP n'est pas encore dans notre dictionnaire, on l'ajoute
            if source_ip not in suspicious_report:
                suspicious_report[source_ip] = []

            # On ajoute les nouvelles raisons sans faire de doublons
            for reason in reasons:
                if reason not in suspicious_report[source_ip]:
                    suspicious_report[source_ip].append(reason)

    return suspicious_report