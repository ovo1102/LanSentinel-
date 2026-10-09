package sec.lansentinel.core.honeypot;

import java.io.IOException;
import java.net.Socket;
import sec.lansentinel.core.alert.AlertEngine;
import sec.lansentinel.core.honeypot.emulator.ServiceEmulator;
import sec.lansentinel.model.AttackEvent;

/**
 * 会话处理器：处理一次攻击者连接的完整生命周期。
 * 连接即记录（触碰诱饵端口本身就可疑），交互数据再追加记录。
 */
public class SessionHandler implements Runnable {

    private final Socket socket;
    private final int honeypotPort;
    private final ServiceEmulator emulator;
    private final AlertEngine alertEngine;

    public SessionHandler(Socket socket, int honeypotPort,
                          ServiceEmulator emulator, AlertEngine alertEngine) {
        this.socket = socket;
        this.honeypotPort = honeypotPort;
        this.emulator = emulator;
        this.alertEngine = alertEngine;
    }

    @Override
    public void run() {
        String srcIp = socket.getInetAddress().getHostAddress();
        int srcPort = socket.getPort();
        try {
            // 第一步：连接本身即事件（扫描器常连接后立即关闭，不会交互）
            alertEngine.recordEvent(new AttackEvent(
                    srcIp, srcPort, honeypotPort, emulator.protocol(), "建立连接"));

            // 第二步：协议伪装交互，骗取更多行为数据
            String detail = emulator.emulate(socket);
            alertEngine.recordEvent(new AttackEvent(
                    srcIp, srcPort, honeypotPort, emulator.protocol(), detail));

        } catch (IOException e) {
            // 攻击者中途断开属正常情况，连接事件已记录
        } finally {
            try {
                socket.close();
            } catch (IOException ignored) {
            }
        }
    }
}
