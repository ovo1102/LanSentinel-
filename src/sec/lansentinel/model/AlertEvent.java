package sec.lansentinel.model;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

/**
 * 告警事件：所有安全模块（扫描/蜜罐/ARP监控）产生的告警统一用此类表示。
 * M1阶段先定义结构，M2由告警引擎统一分发。
 */
public class AlertEvent {

    /** 告警级别 */
    public enum Level {
        INFO,       // 提示
        WARNING,    // 中危
        CRITICAL    // 高危
    }

    private static final DateTimeFormatter FMT = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    private final LocalDateTime time;
    private final Level level;
    private final String source;    // 来源模块，如 "扫描引擎" / "蜜罐" / "ARP监控"
    private final String message;   // 告警描述

    public AlertEvent(Level level, String source, String message) {
        this.time = LocalDateTime.now();
        this.level = level;
        this.source = source;
        this.message = message;
    }

    public LocalDateTime getTime() {
        return time;
    }

    public Level getLevel() {
        return level;
    }

    public String getSource() {
        return source;
    }

    public String getMessage() {
        return message;
    }

    @Override
    public String toString() {
        return "[" + time.format(FMT) + "] [" + level + "] [" + source + "] " + message;
    }
}
