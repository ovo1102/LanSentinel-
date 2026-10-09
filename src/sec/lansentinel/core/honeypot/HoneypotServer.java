package sec.lansentinel.core.honeypot;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import sec.lansentinel.core.alert.AlertEngine;
import sec.lansentinel.core.honeypot.emulator.FtpEmulator;
import sec.lansentinel.core.honeypot.emulator.HttpEmulator;
import sec.lansentinel.core.honeypot.emulator.ServiceEmulator;
import sec.lansentinel.core.honeypot.emulator.SshEmulator;
import sec.lansentinel.core.honeypot.emulator.TelnetEmulator;
import sec.lansentinel.service.ConfigManager;

/**
 * 蜜罐服务器：统一布设/撤防所有诱饵端口。
 */
public class HoneypotServer {

    /** 诱饵端口 -> 伪装协议（高位谐音端口避开权限与冲突） */
    private static final Map<Integer, ServiceEmulator> EMULATORS = Map.of(
            2323, new TelnetEmulator(),
            2222, new SshEmulator(),
            2121, new FtpEmulator(),
            8080, new HttpEmulator()
    );

    private final List<HoneypotListener> listeners = new ArrayList<>();
    private final List<Thread> threads = new ArrayList<>();

    public HoneypotServer(ConfigManager config, AlertEngine alertEngine) {
        for (int port : config.getIntList("honeypot.ports")) {
            ServiceEmulator emulator = EMULATORS.getOrDefault(port, new TelnetEmulator());
            listeners.add(new HoneypotListener(port, emulator, alertEngine));
        }
    }

    /** 布防：启动所有诱饵端口监听 */
    public void startAll() {
        for (HoneypotListener listener : listeners) {
            Thread t = new Thread(listener, "honeypot-" + listener.getPort());
            t.setDaemon(true);
            t.start();
            threads.add(t);
        }
    }

    /** 撤防：停止所有监听 */
    public void stopAll() {
        for (HoneypotListener listener : listeners) {
            listener.stop();
        }
    }
}
