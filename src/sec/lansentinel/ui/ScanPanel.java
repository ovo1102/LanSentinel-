package sec.lansentinel.ui;

import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.io.File;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;
import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JProgressBar;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.JTextField;
import javax.swing.SwingWorker;
import javax.swing.table.DefaultTableModel;
import sec.lansentinel.core.scan.ScanEngine;
import sec.lansentinel.model.HostInfo;
import sec.lansentinel.model.PortInfo;
import sec.lansentinel.service.ConfigManager;
import sec.lansentinel.service.ReportService;
import sec.lansentinel.util.IpUtil;

/**
 * 扫描面板：网段/端口输入、扫描执行（SwingWorker后台线程）、结果表格、报告导出与校验。
 */
public class ScanPanel extends JPanel {

    private final MainFrame app;
    private final JTextField startField = new JTextField(14);
    private final JTextField endField = new JTextField(14);
    private final JTextField portField = new JTextField(22);
    private final JButton scanBtn = new JButton("开始扫描");
    private final JButton exportBtn = new JButton("导出报告");
    private final JButton verifyBtn = new JButton("校验报告");
    private final JProgressBar progressBar = new JProgressBar();
    private final JLabel statusLabel = new JLabel("就绪");

    private final DefaultTableModel resultModel = new DefaultTableModel(
            new Object[]{"IP地址", "状态", "开放端口（Banner）", "风险分"}, 0) {
        @Override
        public boolean isCellEditable(int row, int column) {
            return false;
        }
    };
    private final JTable resultTable = new JTable(resultModel);

    /** 最近一次扫描结果，供报告导出使用 */
    private List<HostInfo> lastResults;

    public ScanPanel(MainFrame app) {
        this.app = app;
        ConfigManager config = app.getConfig();
        startField.setText(config.get("scan.range.start"));
        endField.setText(config.get("scan.range.end"));
        portField.setText(Arrays.stream(config.getIntList("scan.default.ports"))
                .mapToObj(String::valueOf).collect(Collectors.joining(",")));

        setLayout(new BorderLayout(8, 8));
        setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));
        add(buildControlPanel(), BorderLayout.NORTH);
        add(new JScrollPane(resultTable), BorderLayout.CENTER);
        add(buildStatusPanel(), BorderLayout.SOUTH);

        exportBtn.setEnabled(false);
        scanBtn.addActionListener(e -> startScan());
        exportBtn.addActionListener(e -> exportReport());
        verifyBtn.addActionListener(e -> verifyReport());
    }

    private JPanel buildControlPanel() {
        JPanel panel = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 6));
        panel.add(new JLabel("起始IP:"));
        panel.add(startField);
        panel.add(new JLabel("结束IP:"));
        panel.add(endField);
        panel.add(new JLabel("端口:"));
        panel.add(portField);
        panel.add(scanBtn);
        panel.add(exportBtn);
        panel.add(verifyBtn);
        return panel;
    }

    private JPanel buildStatusPanel() {
        JPanel panel = new JPanel(new BorderLayout(8, 0));
        progressBar.setStringPainted(true);
        panel.add(progressBar, BorderLayout.CENTER);
        panel.add(statusLabel, BorderLayout.EAST);
        return panel;
    }

    private void startScan() {
        final List<String> targets;
        final int[] ports;
        try {
            targets = IpUtil.expandRange(startField.getText().trim(), endField.getText().trim());
            ports = parsePorts(portField.getText());
            // 授权校验前置：越界目标直接弹窗拒绝
            for (String ip : targets) {
                app.getAuthGuard().checkTarget(ip);
            }
        } catch (Exception ex) {
            app.showError(ex.getMessage());
            return;
        }

        resultModel.setRowCount(0);
        lastResults = null;
        exportBtn.setEnabled(false);
        scanBtn.setEnabled(false);
        progressBar.setValue(0);
        progressBar.setMaximum(targets.size());
        statusLabel.setText("扫描中...");

        ConfigManager config = app.getConfig();
        ScanEngine engine = new ScanEngine(
                app.getAuthGuard(),
                config.getInt("scan.host.timeout", 800),
                config.getInt("scan.port.timeout", 500),
                config.getInt("scan.banner.timeout", 1500),
                config.getInt("scan.thread.pool", 50),
                config.getIntSet("risk.high.ports"))
                .withAlertEngine(app.getAlertEngine());

        // 耗时扫描放到后台线程，避免阻塞界面事件派发线程
        new SwingWorker<Void, HostInfo>() {
            @Override
            protected Void doInBackground() throws Exception {
                engine.scan(targets, ports, new ScanEngine.ScanListener() {
                    @Override
                    public void onHostScanned(HostInfo host, int finished, int total) {
                        progressBar.setValue(finished);
                        if (host.isAlive()) {
                            publish(host);
                        }
                    }

                    @Override
                    public void onScanFinished(List<HostInfo> results, long elapsedMillis) {
                        lastResults = results;
                        statusLabel.setText("完成，耗时 " + elapsedMillis + " ms");
                    }
                });
                return null;
            }

            @Override
            protected void process(List<HostInfo> hosts) {
                for (HostInfo h : hosts) {
                    resultModel.addRow(new Object[]{
                            h.getIp(), "在线", formatPorts(h), h.getRiskScore()});
                }
            }

            @Override
            protected void done() {
                scanBtn.setEnabled(true);
                exportBtn.setEnabled(lastResults != null);
            }
        }.execute();
    }

    private String formatPorts(HostInfo h) {
        return h.getOpenPorts().stream()
                .map(p -> p.getPort() + (p.getConsistency() == PortInfo.Consistency.MISMATCH ? "[错位]" : ""))
                .collect(Collectors.joining(", "));
    }

    private int[] parsePorts(String text) {
        String[] parts = text.split(",");
        int[] ports = new int[parts.length];
        for (int i = 0; i < parts.length; i++) {
            ports[i] = Integer.parseInt(parts[i].trim());
            if (ports[i] < 1 || ports[i] > 65535) {
                throw new IllegalArgumentException("端口越界: " + ports[i]);
            }
        }
        return ports;
    }

    private void exportReport() {
        if (lastResults == null) {
            return;
        }
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("选择报告保存目录");
        chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
        if (chooser.showSaveDialog(this) != JFileChooser.APPROVE_OPTION) {
            return;
        }
        try {
            Path dir = chooser.getSelectedFile().toPath();
            Path report = new ReportService().exportReport(
                    lastResults, app.getAlertLog(),
                    startField.getText().trim() + " ~ " + endField.getText().trim(), dir);
            JOptionPane.showMessageDialog(this,
                    "报告已导出：\n" + report + "\n\n同时生成了 .sig 签名文件，可用于防篡改校验",
                    "导出成功", JOptionPane.INFORMATION_MESSAGE);
        } catch (Exception ex) {
            app.showError("导出失败：" + ex.getMessage());
        }
    }

    private void verifyReport() {
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("选择要校验的HTML报告");
        chooser.setFileFilter(new javax.swing.filechooser.FileNameExtensionFilter(
                "HTML报告", "html"));
        if (chooser.showOpenDialog(this) != JFileChooser.APPROVE_OPTION) {
            return;
        }
        File file = chooser.getSelectedFile();
        try {
            String result = new ReportService().verifyReport(file.toPath());
            JOptionPane.showMessageDialog(this, result, "完整性校验",
                    result.contains("失败") ? JOptionPane.WARNING_MESSAGE : JOptionPane.INFORMATION_MESSAGE);
        } catch (Exception ex) {
            app.showError("校验失败：" + ex.getMessage());
        }
    }
}
