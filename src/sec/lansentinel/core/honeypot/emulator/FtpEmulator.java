package sec.lansentinel.core.honeypot.emulator;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.Socket;
import java.nio.charset.StandardCharsets;

/**
 * FTP伪装：模拟FTP登录流程，骗取USER/PASS凭据。
 */
public class FtpEmulator implements ServiceEmulator {

    @Override
    public String protocol() {
        return "FTP";
    }

    @Override
    public String emulate(Socket socket) throws IOException {
        java.io.OutputStream out = socket.getOutputStream();
        BufferedReader in = new BufferedReader(
                new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8));

        send(out, "220 ProFTPD Server Ready\r\n");

        String user = "";
        String pass = "";
        String line = in.readLine();   // 期望: USER xxx
        if (line != null && line.toUpperCase().startsWith("USER")) {
            user = line.substring(4).trim();
            send(out, "331 Password required\r\n");
            line = in.readLine();      // 期望: PASS xxx
            if (line != null && line.toUpperCase().startsWith("PASS")) {
                pass = line.substring(4).trim();
            }
        }
        send(out, "530 Login incorrect\r\n");
        return "user=" + safe(user) + " pass=" + safe(pass);
    }

    private void send(java.io.OutputStream out, String text) throws IOException {
        out.write(text.getBytes(StandardCharsets.UTF_8));
        out.flush();
    }

    private String safe(String s) {
        return s.replaceAll("[\\p{Cntrl}]", "");
    }
}
