package sec.lansentinel.ui;

import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.util.List;
import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.SwingUtilities;
import javax.swing.table.DefaultTableModel;
import sec.lansentinel.model.ArpEntry;

/**
 * ARP监控面板：启停定时监控，表格展示当前系统ARP表（IP-MAC映射）。
 * MAC变更或一对多映射的告警会自动进入"告警中心"页签。
 */
public class ArpPanel extends JPanel {

    private final MainFrame app;
    private final JButton startBtn = new JButton("启动监控");
    private final JButton stopBtn = new JButton("停止监控");
    private final JLabel stateLabel = new JLabel("未启动");

    private final DefaultTableModel model = new DefaultTableModel(
            new Object[]{"IP地址", "MAC地址", "类型"}, 0) {
        @Override
        public boolean isCellEditable(int row, int column) {
            return false;
        }
    };
    private final JTable table = new JTable(model);

    public ArpPanel(MainFrame app) {
        this.app = app;
        setLayout(new BorderLayout(8, 8));
        setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));

        JPanel top = new JPanel(new FlowLayout(FlowLayout.LEFT));
        top.add(startBtn);
        top.add(stopBtn);
        top.add(stateLabel);
        stopBtn.setEnabled(false);
        add(top, BorderLayout.NORTH);

        add(new JScrollPane(table), BorderLayout.CENTER);

        startBtn.addActionListener(e -> startMonitor());
        stopBtn.addActionListener(e -> stopMonitor());

        // 每次轮询的快照回调，刷新映射表
        app.getArpMonitor().setSnapshotListener(this::refreshTable);
    }

    private void startMonitor() {
        // 重启一个新的监控实例需要重建，这里直接启动（MainFrame持有同一实例）
        app.getArpMonitor().start();
        startBtn.setEnabled(false);
        stopBtn.setEnabled(true);
        stateLabel.setText("监控中（间隔 " + app.getConfig().getInt("arp.interval", 30) + " 秒）");
    }

    private void stopMonitor() {
        app.getArpMonitor().stop();
        startBtn.setEnabled(true);
        stopBtn.setEnabled(false);
        stateLabel.setText("已停止");
    }

    private void refreshTable(List<ArpEntry> entries) {
        SwingUtilities.invokeLater(() -> {
            model.setRowCount(0);
            for (ArpEntry e : entries) {
                model.addRow(new Object[]{e.getIp(), e.getMac(), e.getType()});
            }
            stateLabel.setText("监控中，最近刷新 " + entries.size() + " 条映射");
        });
    }
}
