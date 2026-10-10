package sec.lansentinel.core.arp;

import java.io.IOException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import sec.lansentinel.core.alert.AlertEngine;
import sec.lansentinel.model.AlertEvent;
import sec.lansentinel.model.ArpEntry;

/**
 * ARP欺骗监控：周期性轮询系统ARP表并与基线比对。
 *
 * 检测原理（两类经典ARP攻击特征）：
 * 1. 同一IP的MAC发生变化 —— 攻击者在冒充该IP（常见于冒充网关）；
 * 2. 同一MAC同时对应多个IP —— 攻击者把自己的MAC塞进多个映射，
 *    典型的中间人/网关仿冒特征。
 *
 * 第一次轮询只建立基线不告警，之后每轮比对差异。
 */
public class ArpMonitor {

    private final AlertEngine alertEngine;
    private final ArpTableParser parser = new ArpTableParser();
    private final int intervalSeconds;
    private ScheduledExecutorService scheduler;

    /** IP -> MAC 基线 */
    private final Map<String, String> ipToMac = new HashMap<>();
    /** MAC -> 已映射的IP集合（用于检测一对多） */
    private final Map<String, Set<String>> macToIps = new HashMap<>();
    /** 是否已建立基线 */
    private boolean baselineReady = false;

    public ArpMonitor(AlertEngine alertEngine, int intervalSeconds) {
        this.alertEngine = alertEngine;
        this.intervalSeconds = intervalSeconds;
    }

    /** 启动定时监控（首次立即执行一次以建立基线） */
    public void start() {
        scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "arp-monitor");
            t.setDaemon(true);
            return t;
        });
        scheduler.scheduleAtFixedRate(this::pollOnce, 0, intervalSeconds, TimeUnit.SECONDS);
        System.out.println("[ARP] 监控已启动，轮询间隔 " + intervalSeconds + " 秒");
    }

    public void stop() {
        if (scheduler != null) {
            scheduler.shutdownNow();
        }
    }

    /** 执行一次真实轮询：读取系统ARP表并检测 */
    public void pollOnce() {
        try {
            detect(parser.parse());
        } catch (IOException e) {
            // 单次轮询失败不应终止定时任务
            System.out.println("[ARP] 轮询失败: " + e.getMessage());
        }
    }

    /**
     * 核心检测逻辑：与当前基线比对并更新基线。
     * 独立为public方法，便于注入模拟数据进行自检。
     */
    public synchronized void detect(List<ArpEntry> current) {
        if (!baselineReady) {
            // 首轮：只建立基线
            for (ArpEntry e : current) {
                ipToMac.put(e.getIp(), e.getMac());
                macToIps.computeIfAbsent(e.getMac(), k -> new HashSet<>()).add(e.getIp());
            }
            baselineReady = true;
            System.out.println("[ARP] 基线已建立，共记录 " + current.size() + " 条IP-MAC映射");
            return;
        }

        for (ArpEntry e : current) {
            String ip = e.getIp();
            String newMac = e.getMac();
            String oldMac = ipToMac.get(ip);

            // 特征1：同一IP的MAC改变
            if (oldMac != null && !oldMac.equals(newMac)) {
                alertEngine.fireAlert(new AlertEvent(AlertEvent.Level.CRITICAL, "ARP监控",
                        ip + " 的MAC由 " + oldMac + " 变为 " + newMac
                        + "，疑似ARP欺骗/冒充（中间人攻击）"));
                // 维护MAC反向索引：移除旧归属
                Set<String> oldOwners = macToIps.get(oldMac);
                if (oldOwners != null) {
                    oldOwners.remove(ip);
                }
            }

            // 特征2：同一MAC已归属其他IP（排除该IP自身已记录的情况）
            Set<String> owners = macToIps.getOrDefault(newMac, new HashSet<>());
            boolean belongsToOther = owners.stream().anyMatch(other -> !other.equals(ip));
            if (belongsToOther) {
                alertEngine.fireAlert(new AlertEvent(AlertEvent.Level.CRITICAL, "ARP监控",
                        "MAC " + newMac + " 同时映射到 " + owners + " 和 " + ip
                        + "，疑似伪造网关进行流量劫持"));
            }

            // 更新基线
            ipToMac.put(ip, newMac);
            macToIps.computeIfAbsent(newMac, k -> new HashSet<>()).add(ip);
        }
    }
}
