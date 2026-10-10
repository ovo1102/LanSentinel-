package sec.lansentinel.core.honeypot.emulator;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.Socket;
import java.nio.charset.StandardCharsets;

/**
 * Telnet伪装：伪造Linux登录提示，骗取攻击者输入的账号密码。
 * 登录永远失败，诱使对方反复尝试（配合R2暴力破解规则）。
 */
public class TelnetEmulator implements ServiceEmulator {

    @Override
    public String protocol() {
        return "TELNET";
    }

    @Override
    public String emulate(Socket socket) throws IOException {
        OutputStream out = socket.getOutputStream();
        BufferedReader in = new BufferedReader(
                new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8));

        send(out, "Ubuntu 18.04.5 LTS\r\n");
        send(out, "login: ");
        String user = "";
        String pass = "";
        // 读取容错：即使对端以RST方式断开导致后半段读取失败，已获得的尝试行为也要留证
        try {
            user = readLine(in);
            send(out, "Password: ");
            pass = readLine(in);
        } catch (IOException ignored) {
            // 对端提前断开，已读到的部分继续作为凭据尝试记录
        }

        // 凭据已获取，此后的发送即使因客户端提前断开而失败，也不能丢弃证据
        try {
            send(out, "\r\nLogin incorrect\r\n");
        } catch (IOException ignored) {
            // 攻击者拿到提示前就断开，属正常行为
        }
        return "user=" + safe(user) + " pass=" + safe(pass);
    }

    private void send(OutputStream out, String text) throws IOException {
        out.write(text.getBytes(StandardCharsets.UTF_8));
        out.flush();
    }

    private String readLine(BufferedReader in) throws IOException {
        String line = in.readLine();
        return line == null ? "" : line;
    }

    /** 防止攻击者输入控制字符污染日志 */
    private String safe(String s) {
        return s.replaceAll("[\\p{Cntrl}]", "");
    }
}
