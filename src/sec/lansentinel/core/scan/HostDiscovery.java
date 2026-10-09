package sec.lansentinel.core.scan;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;

/**
 * 主机存活探测：先尝试ICMP（isReachable），失败后用TCP常用端口兜底。
 *
 * Windows下普通Java进程的 isReachable 实际走TCP/ICMP回退，探测能力有限，
 * 因此增加TCP兜底探测（连135/445/80等常见端口，连通即认为主机在线）。
 */
public class HostDiscovery {

    /** 兜底探测用的常见端口 */
    private static final int[] PROBE_PORTS = {135, 445, 80, 22, 3389};

    private final int timeout;

    public HostDiscovery(int timeout) {
        this.timeout = timeout;
    }

    /** 探测主机是否在线 */
    public boolean isAlive(String ip) {
        // 方式一：ICMP/系统级探测
        try {
            if (InetAddress.getByName(ip).isReachable(timeout)) {
                return true;
            }
        } catch (IOException ignored) {
            // 探测失败继续用TCP兜底
        }
        // 方式二：TCP连接常用端口，任一连通即在线
        for (int port : PROBE_PORTS) {
            try (Socket socket = new Socket()) {
                socket.connect(new InetSocketAddress(ip, port), timeout);
                return true;
            } catch (IOException ignored) {
                // 该端口不通，尝试下一个
            }
        }
        return false;
    }
}
