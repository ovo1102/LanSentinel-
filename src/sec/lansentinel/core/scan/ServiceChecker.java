package sec.lansentinel.core.scan;

import java.util.Map;
import java.util.regex.Pattern;
import sec.lansentinel.model.PortInfo;

/**
 * 服务一致性检查器：比对"端口号的预期服务"与"Banner的实际指纹"。
 *
 * 安全原理：正常服务通常运行在其标准端口上，若某端口的Banner指纹
 * 与该端口的常识服务不符，可能是管理员违规部署，也可能是攻击者
 * 为隐藏后门而使用的高位/错位端口。
 */
public class ServiceChecker {

    /** 端口 -> 预期服务名 */
    private static final Map<Integer, String> EXPECTED = Map.ofEntries(
            Map.entry(21, "FTP"),
            Map.entry(22, "SSH"),
            Map.entry(23, "Telnet"),
            Map.entry(80, "HTTP"),
            Map.entry(443, "HTTPS"),
            Map.entry(3306, "MySQL"),
            Map.entry(3389, "RDP"),
            Map.entry(8080, "HTTP")
    );

    /** Banner指纹 -> 服务名（正则匹配，忽略大小写） */
    private static final Map<Pattern, String> FINGERPRINTS = Map.of(
            Pattern.compile("SSH", Pattern.CASE_INSENSITIVE), "SSH",
            Pattern.compile("FTP", Pattern.CASE_INSENSITIVE), "FTP",
            Pattern.compile("HTTP|Server:", Pattern.CASE_INSENSITIVE), "HTTP",
            Pattern.compile("MySQL|MariaDB", Pattern.CASE_INSENSITIVE), "MySQL"
    );

    /**
     * 执行一致性检查，将结论写回 PortInfo。
     *
     * @return 若发现服务错位，返回告警描述；否则返回 null
     */
    public String check(PortInfo portInfo) {
        if (!portInfo.isOpen() || portInfo.getBanner().isEmpty()) {
            portInfo.setConsistency(PortInfo.Consistency.UNKNOWN);
            return null;
        }
        String expected = EXPECTED.get(portInfo.getPort());
        if (expected == null) {
            portInfo.setConsistency(PortInfo.Consistency.UNKNOWN);
            return null;
        }
        String actual = identify(portInfo.getBanner());
        if (actual == null) {
            portInfo.setConsistency(PortInfo.Consistency.UNKNOWN);
            return null;
        }
        if (expected.equals(actual)) {
            portInfo.setConsistency(PortInfo.Consistency.MATCH);
            return null;
        }
        // 发现错位
        portInfo.setConsistency(PortInfo.Consistency.MISMATCH);
        return "端口 " + portInfo.getPort() + " 预期服务为 " + expected
                + "，但Banner指纹为 " + actual + "（" + portInfo.getBanner()
                + "），疑似服务错位或隐蔽后门";
    }

    /** 根据Banner识别实际服务，识别不了返回 null */
    private String identify(String banner) {
        for (Map.Entry<Pattern, String> entry : FINGERPRINTS.entrySet()) {
            if (entry.getKey().matcher(banner).find()) {
                return entry.getValue();
            }
        }
        return null;
    }
}
