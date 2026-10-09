package sec.lansentinel.core.alert;

import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import sec.lansentinel.model.AlertEvent;
import sec.lansentinel.model.AttackEvent;

/**
 * 规则R1：端口扫描检测。
 * 同一源IP在时间窗口内触碰多个不同诱饵端口，判定为正在扫描网络。
 */
public class PortScanRule implements AlertRule {

    private final int distinctPortThreshold;   // 触发告警的不同端口数
    private final long windowSeconds;          // 判定窗口
    /** 已告警过的IP，防止告警刷屏 */
    private final Set<String> alertedIps = new HashSet<>();

    public PortScanRule(int distinctPortThreshold, long windowSeconds) {
        this.distinctPortThreshold = distinctPortThreshold;
        this.windowSeconds = windowSeconds;
    }

    @Override
    public Optional<AlertEvent> evaluate(AttackEvent event, Map<String, List<AttackEvent>> history) {
        String srcIp = event.getSrcIp();
        if (alertedIps.contains(srcIp)) {
            return Optional.empty();
        }
        LocalDateTime deadline = LocalDateTime.now().minusSeconds(windowSeconds);
        long distinctPorts = history.getOrDefault(srcIp, List.of()).stream()
                .filter(e -> e.getTime().isAfter(deadline))
                .map(AttackEvent::getDestPort)
                .distinct()
                .count();
        if (distinctPorts >= distinctPortThreshold) {
            alertedIps.add(srcIp);
            return Optional.of(new AlertEvent(AlertEvent.Level.CRITICAL, "蜜罐",
                    srcIp + " 正在扫描网络（" + windowSeconds + "秒内触碰 "
                    + distinctPorts + " 个诱饵端口）"));
        }
        return Optional.empty();
    }
}
