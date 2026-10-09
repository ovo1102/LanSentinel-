package sec.lansentinel.model;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * 主机信息：记录一台目标主机的完整扫描结果
 */
public class HostInfo {

    private final String ip;
    private boolean alive;
    /** 线程安全列表：扫描阶段由多个线程并发写入 */
    private final List<PortInfo> ports = new CopyOnWriteArrayList<>();
    /** 风险评分 0~100，由风险评分模块计算 */
    private int riskScore;

    public HostInfo(String ip) {
        this.ip = ip;
    }

    public String getIp() {
        return ip;
    }

    public boolean isAlive() {
        return alive;
    }

    public void setAlive(boolean alive) {
        this.alive = alive;
    }

    public List<PortInfo> getPorts() {
        return ports;
    }

    public void addPort(PortInfo p) {
        ports.add(p);
    }

    /** 返回所有开放端口 */
    public List<PortInfo> getOpenPorts() {
        return ports.stream().filter(PortInfo::isOpen).toList();
    }

    public int getRiskScore() {
        return riskScore;
    }

    public void setRiskScore(int riskScore) {
        this.riskScore = riskScore;
    }

    @Override
    public String toString() {
        if (!alive) {
            return ip + "  [离线]";
        }
        StringBuilder sb = new StringBuilder(ip + "  [在线]  风险分: " + riskScore);
        for (PortInfo p : getOpenPorts()) {
            sb.append("\n    ").append(p);
        }
        return sb.toString();
    }
}
