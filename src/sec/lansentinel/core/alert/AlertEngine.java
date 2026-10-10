package sec.lansentinel.core.alert;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import sec.lansentinel.model.AlertEvent;
import sec.lansentinel.model.AttackEvent;

/**
 * 告警引擎：系统的"总线"角色。
 * 蜜罐、ARP监控等模块只负责把事件推给本引擎，
 * 引擎维护历史行为、执行规则匹配、向监听器分发告警。
 * 各检测模块之间零耦合，符合观察者模式。
 */
public class AlertEngine {

    /** 告警监听器：控制台打印 / GUI告警中心 */
    public interface AlertListener {
        void onAlert(AlertEvent alert);
    }

    /** 原始攻击事件监听器：GUI蜜罐面板用它实时展示所有捕获行为 */
    public interface EventListener {
        void onEvent(AttackEvent event);
    }

    /** 历史窗口时长（秒），超出的事件被清理 */
    private static final long WINDOW_SECONDS = 120;

    private final List<AlertRule> rules = new ArrayList<>();
    private final List<AlertListener> listeners = new ArrayList<>();
    private final List<EventListener> eventListeners = new ArrayList<>();
    /** 各源IP的近期行为历史，key=源IP */
    private final Map<String, List<AttackEvent>> history = new HashMap<>();

    public void addRule(AlertRule rule) {
        rules.add(rule);
    }

    public void addListener(AlertListener listener) {
        listeners.add(listener);
    }

    public void addEventListener(EventListener listener) {
        eventListeners.add(listener);
    }

    /** 记录一条攻击事件并执行规则研判（多线程入口，需同步） */
    public synchronized void recordEvent(AttackEvent event) {
        // 先分发原始事件（蜜罐面板实时展示），再执行规则研判
        for (EventListener l : eventListeners) {
            l.onEvent(event);
        }
        history.computeIfAbsent(event.getSrcIp(), k -> new ArrayList<>()).add(event);
        pruneExpired();
        for (AlertRule rule : rules) {
            Optional<AlertEvent> alert = rule.evaluate(event, history);
            alert.ifPresent(this::fireAlert);
        }
    }

    /**
     * 直接派发一条告警：供ARP监控这类"自身即可判定"、
     * 不经过攻击事件规则链的模块使用。
     */
    public void fireAlert(AlertEvent alert) {
        for (AlertListener listener : listeners) {
            listener.onAlert(alert);
        }
    }

    /** 清理超出时间窗口的历史事件，防止内存无限增长 */
    private void pruneExpired() {
        LocalDateTime deadline = LocalDateTime.now().minusSeconds(WINDOW_SECONDS);
        history.values().forEach(list -> list.removeIf(e -> e.getTime().isBefore(deadline)));
        history.entrySet().removeIf(entry -> entry.getValue().isEmpty());
    }
}
