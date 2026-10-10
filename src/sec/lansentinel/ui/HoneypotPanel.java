package sec.lansentinel.ui;

import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.time.format.DateTimeFormatter;
import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.SwingUtilities;

/**
 * 蜜罐面板：布防/撤防诱饵端口，实时滚动显示捕获到的攻击行为。
 */
public class HoneypotPanel extends JPanel {

    private static final DateTimeFormatter FMT = DateTimeFormatter.ofPattern("HH:mm:ss");

    private final MainFrame app;
    private final JButton armBtn = new JButton("布防蜜罐");
    private final JButton disarmBtn = new JButton("撤防");
    private final JTextArea eventArea = new JTextArea();

    public HoneypotPanel(MainFrame app) {
        this.app = app;
        setLayout(new BorderLayout(8, 8));
        setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));

        JPanel top = new JPanel(new FlowLayout(FlowLayout.LEFT));
        top.add(armBtn);
        top.add(disarmBtn);
        disarmBtn.setEnabled(false);
        add(top, BorderLayout.NORTH);

        eventArea.setEditable(false);
        eventArea.setLineWrap(true);
        add(new JScrollPane(eventArea), BorderLayout.CENTER);

        armBtn.addActionListener(e -> startHoneypot());
        disarmBtn.addActionListener(e -> stopHoneypot());

        // 订阅原始攻击事件（每次连接/交互都会产生），实时追加
        app.getAlertEngine().addEventListener(event ->
            SwingUtilities.invokeLater(() -> {
                eventArea.append("[" + event.getTime().format(FMT) + "] "
                        + event.getSrcIp() + ":" + event.getSrcPort() + " -> :"
                        + event.getDestPort() + "  " + event.getProtocol()
                        + "  " + event.getDetail() + "\n");
            }));
    }

    private void startHoneypot() {
        app.getHoneypotServer().startAll();
        armBtn.setEnabled(false);
        disarmBtn.setEnabled(true);
        eventArea.append("蜜罐已布防，诱饵端口：");
        for (int p : app.getConfig().getIntList("honeypot.ports")) {
            eventArea.append(p + " ");
        }
        eventArea.append("\n（任何对这些端口的连接都将被记录并研判）\n");
    }

    private void stopHoneypot() {
        app.getHoneypotServer().stopAll();
        armBtn.setEnabled(true);
        disarmBtn.setEnabled(false);
        eventArea.append("蜜罐已撤防\n");
    }
}
