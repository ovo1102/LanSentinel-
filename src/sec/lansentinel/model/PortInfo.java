package sec.lansentinel.model;

/**
 * 端口信息：记录单个端口的扫描结果
 */
public class PortInfo {

    /** 端口的预期服务（来自常识知识库），与Banner比对后得出的一致性结论 */
    public enum Consistency {
        UNKNOWN,    // 无Banner，无法判断
        MATCH,      // Banner与端口预期服务一致
        MISMATCH    // Banner与端口预期服务不符，疑似服务错位/后门
    }

    private final int port;
    private boolean open;
    private String banner = "";
    private Consistency consistency = Consistency.UNKNOWN;

    public PortInfo(int port) {
        this.port = port;
    }

    public int getPort() {
        return port;
    }

    public boolean isOpen() {
        return open;
    }

    public void setOpen(boolean open) {
        this.open = open;
    }

    public String getBanner() {
        return banner;
    }

    public void setBanner(String banner) {
        this.banner = banner == null ? "" : banner;
    }

    public Consistency getConsistency() {
        return consistency;
    }

    public void setConsistency(Consistency consistency) {
        this.consistency = consistency;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append(port).append(open ? "/开放" : "/关闭");
        if (!banner.isEmpty()) {
            sb.append("  Banner: ").append(banner);
        }
        if (consistency == Consistency.MISMATCH) {
            sb.append("  [服务错位!]");
        }
        return sb.toString();
    }
}
