package sec.lansentinel.ui;

import java.awt.BorderLayout;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import javax.swing.BorderFactory;
import javax.swing.JFrame;
import javax.swing.JOptionPane;
import javax.swing.JTabbedPane;
import sec.lansentinel.core.alert.AlertEngine;
import sec.lansentinel.core.alert.BruteForceRule;
import sec.lansentinel.core.alert.PortScanRule;
import sec.lansentinel.core.arp.ArpMonitor;
import sec.lansentinel.core.honeypot.HoneypotServer;
import sec.lansentinel.model.AlertEvent;
import sec.lansentinel.service.AuthGuard;
import sec.lansentinel.service.ConfigManager;

/**
 * 系统主窗口：四个功能页签共享同一个告警引擎与业务对象。
 */
public class MainFrame extends JFrame {

    private final ConfigManager config;
    private final AuthGuard authGuard;
    private final AlertEngine alertEngine = new AlertEngine();
    private final HoneypotServer honeypotServer;
    private final ArpMonitor arpMonitor;
    /** 全量告警存档，供报告导出使用 */
    private final List<AlertEvent> alertLog = new CopyOnWriteArrayList<>();

    public MainFrame(ConfigManager config, AuthGuard authGuard) {
        this.config = config;
        this.authGuard = authGuard;

        // 注册蜜罐检测规则（与控制台版一致）
        alertEngine.addRule(new PortScanRule(3, 60));
        alertEngine.addRule(new BruteForceRule(3, 60));
        // 告警统一存档
        alertEngine.addListener(alertLog::add);

        this.honeypotServer = new HoneypotServer(config, alertEngine);
        this.arpMonitor = new ArpMonitor(alertEngine, config.getInt("arp.interval", 30));

        initUi();
    }

    private void initUi() {
        setTitle("LanSentinel 局域网威胁感知系统    授权网段：" + authGuard.getRangeText());
        setSize(960, 640);
        setLocationRelativeTo(null);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);

        JTabbedPane tabs = new JTabbedPane();
        tabs.addTab("网段扫描", new ScanPanel(this));
        tabs.addTab("蜜罐诱捕", new HoneypotPanel(this));
        tabs.addTab("ARP监控", new ArpPanel(this));
        tabs.addTab("告警中心", new AlertPanel(this));
        tabs.setBorder(BorderFactory.createEmptyBorder(6, 6, 6, 6));
        add(tabs, BorderLayout.CENTER);

        // 窗口关闭时停止后台服务
        addWindowListener(new java.awt.event.WindowAdapter() {
            @Override
            public void windowClosing(java.awt.event.WindowEvent e) {
                honeypotServer.stopAll();
                arpMonitor.stop();
            }
        });
    }

    public ConfigManager getConfig() {
        return config;
    }

    public AuthGuard getAuthGuard() {
        return authGuard;
    }

    public AlertEngine getAlertEngine() {
        return alertEngine;
    }

    public HoneypotServer getHoneypotServer() {
        return honeypotServer;
    }

    public ArpMonitor getArpMonitor() {
        return arpMonitor;
    }

    public List<AlertEvent> getAlertLog() {
        return alertLog;
    }

    /** 统一的错误弹窗（供各面板调用） */
    public void showError(String message) {
        JOptionPane.showMessageDialog(this, message, "提示", JOptionPane.WARNING_MESSAGE);
    }
}
