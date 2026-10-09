package sec.lansentinel;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.List;
import sec.lansentinel.core.alert.AlertEngine;
import sec.lansentinel.core.alert.BruteForceRule;
import sec.lansentinel.core.alert.PortScanRule;
import sec.lansentinel.core.honeypot.HoneypotServer;
import sec.lansentinel.core.scan.ScanEngine;
import sec.lansentinel.model.HostInfo;
import sec.lansentinel.service.AuthGuard;
import sec.lansentinel.service.ConfigManager;
import sec.lansentinel.util.IpUtil;

/**
 * LanSentinel —— 局域网威胁感知系统
 *
 * 运行模式：
 *   java sec.lansentinel.Main scan      M1 网段扫描演示
 *   java sec.lansentinel.Main honeypot  M2 蜜罐诱捕演示（含模拟攻击自检）
 */
public class Main {

    public static void main(String[] args) throws Exception {
        System.out.println("==============================================");
        System.out.println("   LanSentinel 局域网威胁感知系统 (控制台版)");
        System.out.println("==============================================");

        ConfigManager config = new ConfigManager(Path.of("resources/config.properties"));
        AuthGuard authGuard = new AuthGuard(config);
        System.out.println("授权网段: " + authGuard.getRangeText());

        String mode = args.length > 0 ? args[0] : "scan";
        if ("honeypot".equalsIgnoreCase(mode)) {
            runHoneypotDemo(config);
        } else {
            runScanDemo(config, authGuard);
        }
    }

    // ==================== M1: 网段扫描演示 ====================

    private static void runScanDemo(ConfigManager config, AuthGuard authGuard) throws Exception {
        // 授权校验测试：尝试扫描网段外目标，应被拒绝
        System.out.println("\n--- 授权校验测试 ---");
        try {
            authGuard.checkTarget("192.168.1.1");
            System.out.println("异常：越界目标未被拦截！");
        } catch (SecurityException e) {
            System.out.println(e.getMessage());
        }

        String start = config.get("scan.range.start");
        String end = config.get("scan.range.end");
        List<String> targets = IpUtil.expandRange(start, end);
        int[] ports = config.getIntList("scan.default.ports");
        System.out.println("\n--- 开始扫描 " + start + " ~ " + end
                + "（共 " + targets.size() + " 台主机, " + ports.length + " 个端口） ---");

        ScanEngine engine = new ScanEngine(
                authGuard,
                config.getInt("scan.host.timeout", 800),
                config.getInt("scan.port.timeout", 500),
                config.getInt("scan.banner.timeout", 1500),
                config.getInt("scan.thread.pool", 50),
                config.getIntSet("risk.high.ports"));

        engine.scan(targets, ports, new ScanEngine.ScanListener() {
            @Override
            public void onHostScanned(HostInfo host, int finished, int total) {
                if (host.isAlive()) {
                    System.out.println("\n发现主机: " + host);
                }
                System.out.print("\r扫描进度: " + finished + "/" + total);
            }

            @Override
            public void onScanFinished(List<HostInfo> results, long elapsedMillis) {
                long alive = results.stream().filter(HostInfo::isAlive).count();
                System.out.println("\n\n--- 扫描完成 ---");
                System.out.println("耗时: " + elapsedMillis + " ms");
                System.out.println("在线主机: " + alive + " / " + results.size());
            }
        });
    }

    // ==================== M2: 蜜罐诱捕演示 ====================

    private static void runHoneypotDemo(ConfigManager config) throws Exception {
        // 1. 组装告警引擎：注册规则与告警输出
        AlertEngine alertEngine = new AlertEngine();
        alertEngine.addRule(new PortScanRule(3, 60));      // R1: 60秒触碰3个端口=扫描
        alertEngine.addRule(new BruteForceRule(3, 60));    // R2: 60秒尝试3组凭据=爆破
        alertEngine.addListener(alert ->
                System.out.println("\n>>> 触发告警 " + alert));

        // 2. 布设蜜罐
        HoneypotServer server = new HoneypotServer(config, alertEngine);
        server.startAll();
        Thread.sleep(500);   // 等待各端口监听就绪

        // 3. 模拟攻击者，验证检测规则（真实部署时此步骤由攻击方触发）
        simulateAttacker();

        // 4. 等待事件处理完成后撤防
        Thread.sleep(1000);
        server.stopAll();
        System.out.println("\n--- 蜜罐自检完成 ---");
    }

    /** 模拟攻击者：多次爆破Telnet + 触碰多个诱饵端口 */
    private static void simulateAttacker() {
        System.out.println("\n--- 模拟攻击者行为（自检） ---");
        String attacker = "127.0.0.1";

        // 行为1：对Telnet诱饵连续尝试3组凭据 -> 应触发R2暴力破解告警
        for (int i = 1; i <= 3; i++) {
            telnetLogin(attacker, 2323, "admin" + i, "123456");
        }
        // 行为2：快速触碰SSH、FTP诱饵端口 -> 应触发R1端口扫描告警
        sshProbe(attacker, 2222);
        ftpLogin(attacker, 2121, "root", "root");
    }

    private static void telnetLogin(String host, int port, String user, String pass) {
        try (Socket s = new Socket(host, port)) {
            s.setSoTimeout(3000);
            OutputStream out = s.getOutputStream();
            // 伪装层依次读取两行，一次性发送即可
            out.write((user + "\r\n" + pass + "\r\n").getBytes(StandardCharsets.UTF_8));
            out.flush();
            drain(s);
        } catch (IOException e) {
            System.out.println("自检连接失败: " + e.getMessage());
        }
    }

    private static void sshProbe(String host, int port) {
        try (Socket s = new Socket(host, port)) {
            s.setSoTimeout(3000);
            BufferedReader in = new BufferedReader(
                    new InputStreamReader(s.getInputStream(), StandardCharsets.UTF_8));
            in.readLine();   // 读取服务端Banner
            s.getOutputStream().write("SSH-2.0-libssh_0.9.6\r\n".getBytes(StandardCharsets.UTF_8));
            s.getOutputStream().flush();
        } catch (IOException e) {
            System.out.println("自检连接失败: " + e.getMessage());
        }
    }

    private static void ftpLogin(String host, int port, String user, String pass) {
        try (Socket s = new Socket(host, port)) {
            s.setSoTimeout(3000);
            BufferedReader in = new BufferedReader(
                    new InputStreamReader(s.getInputStream(), StandardCharsets.UTF_8));
            OutputStream out = s.getOutputStream();
            in.readLine();   // 220 欢迎语
            out.write(("USER " + user + "\r\n").getBytes(StandardCharsets.UTF_8));
            out.flush();
            in.readLine();   // 331
            out.write(("PASS " + pass + "\r\n").getBytes(StandardCharsets.UTF_8));
            out.flush();
            in.readLine();   // 530
        } catch (IOException e) {
            System.out.println("自检连接失败: " + e.getMessage());
        }
    }

    /** 读空服务端响应（直到超时），保证交互流程完整 */
    private static void drain(Socket s) {
        try {
            s.getInputStream().read(new byte[512]);
        } catch (IOException ignored) {
        }
    }
}
