package sec.lansentinel.core.scan;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import sec.lansentinel.core.alert.AlertEngine;
import sec.lansentinel.model.HostInfo;
import sec.lansentinel.model.PortInfo;
import sec.lansentinel.service.AuthGuard;

/**
 * 扫描引擎：负责整个网段扫描任务的调度。
 *
 * 流程：授权校验 -> 主机存活探测 -> 端口扫描(线程池并发) -> 风险评分 -> 结果回调
 */
public class ScanEngine {

    /** 扫描进度监听器：M1阶段由控制台实现，M4阶段换成GUI面板 */
    public interface ScanListener {
        /** 每完成一台主机回调一次 */
        void onHostScanned(HostInfo host, int finished, int total);

        /** 全部完成回调 */
        void onScanFinished(List<HostInfo> results, long elapsedMillis);
    }

    private final AuthGuard authGuard;
    private final HostDiscovery hostDiscovery;
    private final BannerGrabber bannerGrabber;
    private final ServiceChecker serviceChecker;
    private final int threadPoolSize;
    private final int portConnectTimeout;
    private final Set<Integer> highRiskPorts;
    /** 可选注入：错位服务等扫描告警统一汇入 */
    private AlertEngine alertEngine;

    public ScanEngine(AuthGuard authGuard, int hostTimeout, int portTimeout,
                      int bannerTimeout, int threadPoolSize, Set<Integer> highRiskPorts) {
        this.authGuard = authGuard;
        this.hostDiscovery = new HostDiscovery(hostTimeout);
        this.portConnectTimeout = portTimeout;
        this.bannerGrabber = new BannerGrabber(bannerTimeout);
        this.serviceChecker = new ServiceChecker();
        this.threadPoolSize = threadPoolSize;
        this.highRiskPorts = highRiskPorts;
    }

    /** 注入告警引擎后，扫描发现的服务错位等问题将进入统一告警中心 */
    public ScanEngine withAlertEngine(AlertEngine alertEngine) {
        this.alertEngine = alertEngine;
        return this;
    }

    /**
     * 扫描一组目标IP的指定端口。
     * 所有目标先经过授权校验，任一越界立即整体拒绝。
     */
    public List<HostInfo> scan(List<String> targets, int[] ports, ScanListener listener)
            throws InterruptedException {
        // 授权校验：任何越界目标都会抛出 SecurityException
        for (String ip : targets) {
            authGuard.checkTarget(ip);
        }

        long startTime = System.currentTimeMillis();
        List<HostInfo> results = new ArrayList<>();
        ExecutorService pool = Executors.newFixedThreadPool(threadPoolSize);

        int total = targets.size();
        int[] finished = {0};   // 计数器，lambda中使用数组绕过final限制

        for (String ip : targets) {
            HostInfo host = new HostInfo(ip);
            results.add(host);
            pool.execute(() -> {
                host.setAlive(hostDiscovery.isAlive(ip));
                if (host.isAlive()) {
                    // 在线主机才扫端口，离线主机跳过以节省时间
                    new PortScanner(host, ports, portConnectTimeout,
                                    bannerGrabber, serviceChecker, alertEngine).run();
                    host.setRiskScore(calculateRisk(host));
                }
                synchronized (finished) {
                    finished[0]++;
                    listener.onHostScanned(host, finished[0], total);
                }
            });
        }

        pool.shutdown();
        pool.awaitTermination(10, TimeUnit.MINUTES);
        long elapsed = System.currentTimeMillis() - startTime;
        listener.onScanFinished(results, elapsed);
        return results;
    }

    /**
     * 风险评分模型（0~100）：
     * 每个高危端口 +25 分，普通开放端口 +5 分，存在服务错位 +20 分，满分封顶100。
     */
    private int calculateRisk(HostInfo host) {
        int score = 0;
        for (PortInfo p : host.getOpenPorts()) {
            score += highRiskPorts.contains(p.getPort()) ? 25 : 5;
            if (p.getConsistency() == PortInfo.Consistency.MISMATCH) {
                score += 20;
            }
        }
        return Math.min(score, 100);
    }
}
