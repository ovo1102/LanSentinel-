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
 * 规则R2：暴力破解检测。
 * 同一源IP在时间窗口内提交多组凭据，判定为口令爆破。
 * （蜜罐的登录永远失败，正常用户不会反复尝试，反复尝试即攻击）
 */
public class BruteForceRule implements AlertRule {

    /** 凭据类事件的detail特征前缀 */
    private static final String CREDENTIAL_MARK = "user=";

    private final int attemptThreshold;
    private final long windowSeconds;
    private final Set<String> alertedIps = new HashSet<>();

    public BruteForceRule(int attemptThreshold, long windowSeconds) {
        this.attemptThreshold = attemptThreshold;
        this.windowSeconds = windowSeconds;
    }

    @Override
    public Optional<AlertEvent> evaluate(AttackEvent event, Map<String, List<AttackEvent>> history) {
        String srcIp = event.getSrcIp();
        if (alertedIps.contains(srcIp)) {
            return Optional.empty();
        }
        LocalDateTime deadline = LocalDateTime.now().minusSeconds(windowSeconds);
        long attempts = history.getOrDefault(srcIp, List.of()).stream()
                .filter(e -> e.getTime().isAfter(deadline))
                .filter(e -> e.getDetail().startsWith(CREDENTIAL_MARK))
                .count();
        if (attempts >= attemptThreshold) {
            alertedIps.add(srcIp);
            return Optional.of(new AlertEvent(AlertEvent.Level.WARNING, "蜜罐",
                    srcIp + " 正在进行暴力破解（" + windowSeconds + "秒内尝试 "
                    + attempts + " 组凭据）"));
        }
        return Optional.empty();
    }
}
