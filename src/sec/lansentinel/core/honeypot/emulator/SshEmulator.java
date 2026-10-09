package sec.lansentinel.core.honeypot.emulator;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.Socket;
import java.nio.charset.StandardCharsets;

/**
 * SSH伪装：发送服务端Banner，读取并记录攻击者的客户端Banner。
 * 客户端Banner可暴露攻击工具指纹（如 libssh、paramiko、Go等）。
 */
public class SshEmulator implements ServiceEmulator {

    @Override
    public String protocol() {
        return "SSH";
    }

    @Override
    public String emulate(Socket socket) throws IOException {
        // SSH协议规定服务端先发送版本标识行
        socket.getOutputStream().write("SSH-2.0-OpenSSH_7.4\r\n".getBytes(StandardCharsets.UTF_8));
        socket.getOutputStream().flush();

        BufferedReader in = new BufferedReader(
                new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8));
        String clientBanner = in.readLine();
        if (clientBanner == null) {
            clientBanner = "";
        }
        return "client=" + clientBanner.replaceAll("[\\p{Cntrl}]", "");
    }
}
