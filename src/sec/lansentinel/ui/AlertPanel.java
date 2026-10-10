package sec.lansentinel.ui;

import java.time.format.DateTimeFormatter;
import javax.swing.BorderFactory;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.SwingUtilities;
import javax.swing.table.DefaultTableModel;

/**
 * 告警中心：所有模块（扫描/蜜罐/ARP）的告警实时汇聚展示。
 */
public class AlertPanel extends JPanel {

    private static final DateTimeFormatter FMT = DateTimeFormatter.ofPattern("HH:mm:ss");

    private final DefaultTableModel model = new DefaultTableModel(
            new Object[]{"时间", "级别", "来源", "告警描述"}, 0) {
        @Override
        public boolean isCellEditable(int row, int column) {
            return false;
        }
    };
    private final JTable table = new JTable(model);

    public AlertPanel(MainFrame app) {
        setLayout(new java.awt.BorderLayout());
        setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));

        table.getColumnModel().getColumn(0).setPreferredWidth(80);
        table.getColumnModel().getColumn(1).setPreferredWidth(80);
        table.getColumnModel().getColumn(2).setPreferredWidth(80);
        table.getColumnModel().getColumn(3).setPreferredWidth(600);
        add(new JScrollPane(table), java.awt.BorderLayout.CENTER);

        // 告警可能由任意后台线程产生，统一切回事件派发线程更新界面
        app.getAlertEngine().addListener(alert -> SwingUtilities.invokeLater(() ->
            model.addRow(new Object[]{
                    alert.getTime().format(FMT),
                    alert.getLevel().name(),
                    alert.getSource(),
                    alert.getMessage()})));
    }
}
