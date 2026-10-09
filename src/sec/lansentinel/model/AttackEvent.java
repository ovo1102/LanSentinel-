package sec.lansentinel.model;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

/**
 * 攻击事件：蜜罐捕获到的一次连接/交互行为。
 */
public class AttackEvent {

    private static final DateTimeFormatter FMT = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    private final LocalDateTime time;
    private final String srcIp;      // 攻击来源IP
    private final int srcPort;       // 来源端口
    private final int destPort;      // 被攻击的诱饵端口
    private final String protocol;   // 伪装协议：TELNET / SSH / FTP / HTTP
    private final String detail;     // 捕获的交互数据（如账号密码、客户端指纹）

    public AttackEvent(String srcIp, int srcPort, int destPort, String protocol, String detail) {
        this.time = LocalDateTime.now();
        this.srcIp = srcIp;
        this.srcPort = srcPort;
        this.destPort = destPort;
        this.protocol = protocol;
        this.detail = detail;
    }

    public LocalDateTime getTime() {
        return time;
    }

    public String getSrcIp() {
        return srcIp;
    }

    public int getSrcPort() {
        return srcPort;
    }

    public int getDestPort() {
        return destPort;
    }

    public String getProtocol() {
        return protocol;
    }

    public String getDetail() {
        return detail;
    }

    @Override
    public String toString() {
        return time.format(FMT) + " | " + srcIp + ":" + srcPort + " -> :" + destPort
                + " | " + protocol + " | " + detail;
    }
}
