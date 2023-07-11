package common

import "strings"

func ProtocolName(port int) string {
	protocols := map[int]string{
		21:    "FTP",
		22:    "SSH",
		23:    "Telnet",
		25:    "SMTP",
		53:    "DNS",
		80:    "HTTP",
		110:   "POP3",
		143:   "IMAP",
		443:   "HTTPS",
		3389:  "RDP",
		67:    "DHCP",
		68:    "DHCP",
		161:   "SNMP",
		162:   "SNMP",
		123:   "NTP",
		389:   "LDAP",
		548:   "AFP",
		554:   "RTSP",
		3306:  "MySQL",
		5432:  "PostgreSQL",
		6379:  "Redis",
		5060:  "SIP",
		5061:  "SIP",
		2049:  "NFS",
		9418:  "Git",
		6667:  "IRC",
		5222:  "XMPP",
		5223:  "XMPP",
		25565: "Minecraft",
	}

	protocol, exists := protocols[port]
	if exists {
		return strings.ToLower(protocol)
	}
	return strings.ToLower("Unknown")
}
