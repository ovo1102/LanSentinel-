package sec.lansentinel.model;

import java.util.Objects;

/**
 * ARP表项：一条 IP-MAC 映射记录。
 */
public class ArpEntry {

    private final String ip;
    private final String mac;   // 统一小写短横线格式，如 aa-bb-cc-dd-ee-ff
    private final String type;  // static / dynamic

    public ArpEntry(String ip, String mac, String type) {
        this.ip = ip;
        this.mac = mac.toLowerCase();
        this.type = type;
    }

    public String getIp() {
        return ip;
    }

    public String getMac() {
        return mac;
    }

    public String getType() {
        return type;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof ArpEntry other)) {
            return false;
        }
        return Objects.equals(ip, other.ip) && Objects.equals(mac, other.mac);
    }

    @Override
    public int hashCode() {
        return Objects.hash(ip, mac);
    }

    @Override
    public String toString() {
        return ip + "  " + mac + "  " + type;
    }
}
