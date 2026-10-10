package sec.lansentinel.core.honeypot.emulator;

import java.io.IOException;
import java.io.InputStream;
import java.net.Socket;
import java.nio.charset.StandardCharsets;

/**
 * HTTP伪装：伪造"路由器管理后台"登录页，记录攻击者的请求与提交的凭据。
 */
public class HttpEmulator implements ServiceEmulator {

    /** 伪造的路由器登录页（引导攻击者提交账号密码） */
    private static final String FAKE_PAGE = """
            HTTP/1.1 200 OK\r
            Content-Type: text/html; charset=UTF-8\r
            Connection: close\r
            \r
            <html><head><title>Router Admin</title></head><body>
            <h3>Wireless Router Login</h3>
            <form method="POST" action="/login">
            User: <input name="user"><br>
            Pass: <input name="pass" type="password"><br>
            <input type="submit" value="Login">
            </form></body></html>""";

    @Override
    public String protocol() {
        return "HTTP";
    }

    @Override
    public String emulate(Socket socket) throws IOException {
        InputStream in = socket.getInputStream();
        byte[] buf = new byte[2048];
        int len = in.read(buf);   // 读取HTTP请求，超时由SoTimeout兜底
        String request = len > 0 ? new String(buf, 0, len, StandardCharsets.ISO_8859_1) : "";

        // 提取请求首行（GET /admin HTTP/1.1）与可能的POST凭据
        String firstLine = request.lines().findFirst().orElse("").trim();
        String credential = extractCredential(request);

        // 回传伪造页面失败（客户端提前断开）不影响请求证据留存
        try {
            socket.getOutputStream().write(FAKE_PAGE.getBytes(StandardCharsets.UTF_8));
            socket.getOutputStream().flush();
        } catch (IOException ignored) {
        }

        return credential.isEmpty() ? "request=" + firstLine
                                    : "request=" + firstLine + " " + credential;
    }

    /** 从POST请求体中提取 user=xxx pass=yyy 形式的凭据 */
    private String extractCredential(String request) {
        int bodyStart = request.indexOf("\r\n\r\n");
        if (bodyStart < 0) {
            return "";
        }
        String body = request.substring(bodyStart + 4);
        String user = pickParam(body, "user");
        String pass = pickParam(body, "pass");
        if (user.isEmpty() && pass.isEmpty()) {
            return "";
        }
        return "user=" + user + " pass=" + pass;
    }

    private String pickParam(String body, String key) {
        for (String pair : body.split("&")) {
            int eq = pair.indexOf('=');
            if (eq > 0 && pair.substring(0, eq).equalsIgnoreCase(key)) {
                return pair.substring(eq + 1).replaceAll("[\\p{Cntrl}]", "");
            }
        }
        return "";
    }
}
