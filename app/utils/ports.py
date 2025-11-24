#Top de puertos y servicios mas usados segun la IANA

COMMON_SERVICES = {
    # Puertos bien conocidos (0–1023)
    20: "ftp-data",
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    37: "time",
    49: "tacacs",
    53: "dns",
    67: "dhcp-server",
    68: "dhcp-client",
    69: "tftp",
    80: "http",
    110: "pop3",
    111: "rpcbind",
    119: "nntp",
    123: "ntp",
    135: "msrpc",
    137: "netbios-ns",
    138: "netbios-dgm",
    139: "netbios-ssn",
    143: "imap",
    161: "snmp",
    162: "snmp-trap",
    179: "bgp",
    389: "ldap",
    443: "https",
    445: "smb",
    465: "smtps",
    500: "isakmp",
    514: "syslog",
    515: "lpd",
    520: "rip",
    546: "dhcpv6-client",
    547: "dhcpv6-server",
    587: "submission",
    623: "ipmi",
    631: "ipp",
    636: "ldaps",
    873: "rsync",
    902: "vmware-auth",
    989: "ftps-data",
    990: "ftps",
    993: "imaps",
    995: "pop3s",

    # Puertos registrados importantes (1024–49151)
    1025: "nsr",
    1080: "socks-proxy",
    1194: "openvpn",
    1433: "mssql",
    1434: "mssql-monitoring",
    1521: "oracle",
    1701: "l2tp",
    1723: "pptp",
    1812: "radius",
    1813: "radius-accounting",
    1883: "mqtt",
    2049: "nfs",
    2375: "docker",
    2376: "docker-ssl",
    2483: "oracle-tcps",
    3000: "nodejs",
    3074: "xbox-live",
    3128: "squid",
    3268: "global-catalog",
    3306: "mysql",
    3389: "rdp",
    3478: "stun",
    3690: "svn",
    4369: "epmd",
    4500: "ipsec-nat-traversal",
    5000: "upnp",
    5060: "sip",
    5061: "sips",
    5432: "postgresql",
    5500: "vnc-Alt",
    5601: "kibana",
    5672: "rabbitmq",
    5683: "coap",
    5900: "vnc",
    5984: "couchdb",
    6379: "redis",
    6667: "irc",
    7001: "weblogic",
    7002: "weblogic-ssl",
    7200: "fdes",
    7443: "https-alt",
    8000: "http-alt",
    8008: "http-web",
    8080: "proxy-http",
    8081: "http-panel",
    8161: "activemq",
    8443: "https-alt",
    8888: "dashboard",
    9000: "sonarqube",
    9090: "websmi",
    9100: "printer-raw",
    9200: "elasticsearch",
    9300: "elastic-node",
    9418: "git",
    11211: "memcached",

    # Bases de datos
    27017: "mongodb",
    27018: "mongodb-shard",
    27019: "mongodb-config",
    28017: "mongodb-admin",

    # Empresariales
    50000: "sap",
    50070: "hadoop-hdfs",
    50075: "hadoop-datanode",
    50090: "hadoop-secondary",
    61616: "activemq-openwire"
}


# Validaciones
def validate_port(port: int) -> bool:
    """
    Valida que el puerto esté dentro del rango IANA oficial.
    """
    return isinstance(port, int) and 1 <= port <= 65535


def normalize_protocol(proto: str) -> str:
    """
    Normaliza el protocolo y valida que sea TCP o UDP.
    """
    if not proto:
        raise ValueError("No se especificó protocolo")

    p = proto.strip().lower()
    if p not in ("tcp", "udp"):
        raise ValueError(f"Protocolo inválido: {proto}")

    return p


def guess_service(port: int) -> str | None:
    """
    Devuelve el servicio frecuente según IANA/Nmap.
    """
    if not validate_port(port):
        return None

    return COMMON_SERVICES.get(port)


def port_info(port: int) -> dict:
    """
    Devuelve información útil sobre un puerto.
    """
    if not validate_port(port):
        raise ValueError(f"Puerto inválido: {port}")

    service = COMMON_SERVICES.get(port, "unknown")

    return {
        "port": port,
        "service": service,
        "is_common": port in COMMON_SERVICES
    }


