package sec.lansentinel.core.scan;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import sec.lansentinel.core.alert.AlertEngine;
import sec.lansentinel.model.AlertEvent;
import sec.lansentinel.model.HostInfo;
import sec.lansentinel.model.PortInfo;

/**
 * 端口扫描任务：扫描单台主机的一组端口，对开放端口抓取Banner并做一致性检查。
 * 实现 Runnable，由扫描引擎的线程池调度执行。
 */
public class PortScanner implements Runnable {

    private final HostInfo host;
    private final int[] ports;
    private final int connectTimeout;
    private final BannerGrabber bannerGrabber;
    private final ServiceChecker serviceChecker;
    /** 告警引擎可为空（纯扫描场景），错位事件统一汇入告警中心 */
    private final AlertEngine alertEngine;

    public PortScanner(HostInfo host, int[] ports, int connectTimeout,
                       BannerGrabber bannerGrabber, ServiceChecker serviceChecker,
                       AlertEngine alertEngine) {
        this.host = host;
        this.ports = ports;
        this.connectTimeout = connectTimeout;
        this.bannerGrabber = bannerGrabber;
        this.serviceChecker = serviceChecker;
        this.alertEngine = alertEngine;
    }

    @Override
    public void run() {
        for (int port : ports) {
            PortInfo info = new PortInfo(port);
            info.setOpen(isPortOpen(host.getIp(), port));
            if (info.isOpen()) {
                // 开放端口进一步抓取Banner并检查服务一致性
                info.setBanner(bannerGrabber.grab(host.getIp(), port));
                String mismatchAlert = serviceChecker.check(info);
                if (mismatchAlert != null && alertEngine != null) {
                    alertEngine.fireAlert(new AlertEvent(
                            AlertEvent.Level.WARNING, "扫描引擎",
                            host.getIp() + " " + mismatchAlert));
                }
            }
            host.addPort(info);
        }
    }

    /** TCP connect 探测端口是否开放 */
    private boolean isPortOpen(String ip, int port) {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(ip, port), connectTimeout);
            return true;
        } catch (IOException e) {
            return false;
        }
    }
}
