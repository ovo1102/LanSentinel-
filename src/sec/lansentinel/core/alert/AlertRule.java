package sec.lansentinel.core.alert;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import sec.lansentinel.model.AlertEvent;
import sec.lansentinel.model.AttackEvent;

/**
 * 告警规则接口：蜜罐捕获的攻击事件会依次交给所有规则研判。
 * 新增检测能力时只需实现本接口并注册到 AlertEngine，无需改动现有代码。
 */
public interface AlertRule {

    /**
     * 研判一条攻击事件。
     *
     * @param event   当前事件
     * @param history 各源IP的历史事件（已由引擎维护，key=源IP）
     * @return 命中规则则返回告警，否则返回空
     */
    Optional<AlertEvent> evaluate(AttackEvent event, Map<String, List<AttackEvent>> history);
}
