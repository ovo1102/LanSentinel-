package sec.lansentinel.core.honeypot;

import java.io.IOException;
import java.net.BindException;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import sec.lansentinel.core.alert.AlertEngine;
import sec.lansentinel.core.honeypot.emulator.ServiceEmulator;

/**
 * 蜜罐监听器：在单个诱饵端口上 accept 连接，每个连接交给线程池处理。
 * 一个端口对应一个监听线程，互不阻塞。
 */
public class HoneypotListener implements Runnable {

    private final int port;
    private final ServiceEmulator emulator;
    private final AlertEngine alertEngine;
    private final ExecutorService sessionPool = Executors.newCachedThreadPool();
    private volatile boolean running = true;
    private volatile ServerSocket server;

    public HoneypotListener(int port, ServiceEmulator emulator, AlertEngine alertEngine) {
        this.port = port;
        this.emulator = emulator;
        this.alertEngine = alertEngine;
    }

    @Override
    public void run() {
        try (ServerSocket serverSocket = new ServerSocket(port)) {
            this.server = serverSocket;
            System.out.println("[蜜罐] 端口 " + port + " 已布设诱饵（" + emulator.protocol() + "）");
            while (running) {
                Socket attacker = serverSocket.accept();
                // 关键保护：攻击者连上不发数据时，30秒后自动断开，防止线程被耗尽
                attacker.setSoTimeout(30_000);
                sessionPool.execute(new SessionHandler(attacker, port, emulator, alertEngine));
            }
        } catch (BindException e) {
            System.out.println("[蜜罐] 端口 " + port + " 被占用，跳过该诱饵");
        } catch (IOException e) {
            if (running) {
                System.out.println("[蜜罐] 端口 " + port + " 监听异常: " + e.getMessage());
            }
        }
    }

    public void stop() {
        running = false;
        // 关闭ServerSocket使阻塞中的accept()立即退出
        if (server != null) {
            try {
                server.close();
            } catch (IOException ignored) {
            }
        }
        sessionPool.shutdownNow();
    }

    public int getPort() {
        return port;
    }
}
