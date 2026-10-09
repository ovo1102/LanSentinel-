package sec.lansentinel.core.scan;

import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;

/**
 * 服务Banner抓取：连接开放端口后读取服务自报信息，用于服务识别与一致性检查。
 */
public class BannerGrabber {

    private final int timeout;

    public BannerGrabber(int timeout) {
        this.timeout = timeout;
    }

    /**
     * 抓取指定端口的Banner。
     * 对于SSH/FTP等主动推送Banner的协议直接读取；
     * 对于HTTP等被动协议，先发送一个最小请求再读取响应。
     *
     * @return 抓到的Banner（单行，已截断过长内容），抓不到返回空串
     */
    public String grab(String ip, int port) {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(ip, port), timeout);
            socket.setSoTimeout(timeout);

            // HTTP类服务不会主动推送Banner，需要先发请求触发响应
            if (port == 80 || port == 8080 || port == 8000) {
                socket.getOutputStream().write(
                    "HEAD / HTTP/1.0\r\n\r\n".getBytes(StandardCharsets.UTF_8));
                socket.getOutputStream().flush();
            }

            InputStream in = socket.getInputStream();
            byte[] buf = new byte[256];
            int len = in.read(buf);   // 阻塞读取，超时由SoTimeout兜底
            if (len <= 0) {
                return "";
            }
            // 只取第一行，去除不可见字符，避免日志被恶意Banner污染
            String raw = new String(buf, 0, len, StandardCharsets.ISO_8859_1);
            String firstLine = raw.lines().findFirst().orElse("");
            return firstLine.replaceAll("[\\p{Cntrl}]", "").trim();
        } catch (IOException e) {
            return "";   // 连接成功但读不到Banner属正常情况
        }
    }
}
