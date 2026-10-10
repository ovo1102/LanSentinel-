package sec.lansentinel.service;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;
import sec.lansentinel.model.AlertEvent;
import sec.lansentinel.model.HostInfo;
import sec.lansentinel.model.PortInfo;
import sec.lansentinel.util.HashUtil;

/**
 * 报告服务：导出HTML扫描报告并生成SHA-256签名文件，支持事后完整性校验（防篡改）。
 */
public class ReportService {

    private static final DateTimeFormatter FMT = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
    private static final DateTimeFormatter FILE_FMT = DateTimeFormatter.ofPattern("yyyyMMdd_HHmmss");

    /**
     * 导出报告。
     *
     * @return 生成的HTML报告路径；同目录下还会生成 .sig 签名文件
     */
    public Path exportReport(List<HostInfo> hosts, List<AlertEvent> alerts,
                             String rangeText, Path outputDir) throws IOException {
        Files.createDirectories(outputDir);
        String fileName = "report_" + LocalDateTime.now().format(FILE_FMT) + ".html";
        Path reportFile = outputDir.resolve(fileName);

        String html = buildHtml(hosts, alerts, rangeText);
        Files.writeString(reportFile, html, StandardCharsets.UTF_8);

        // 生成与报告配套的SHA-256签名文件
        String hash = HashUtil.sha256OfFile(reportFile);
        Files.writeString(Path.of(reportFile + ".sig"),
                "SHA-256: " + hash + System.lineSeparator()
                + "file: " + fileName + System.lineSeparator()
                + "time: " + LocalDateTime.now().format(FMT) + System.lineSeparator(),
                StandardCharsets.UTF_8);
        return reportFile;
    }

    /**
     * 校验报告是否被篡改：重新计算哈希与 .sig 文件比对。
     *
     * @return 校验结果描述
     */
    public String verifyReport(Path reportFile) throws IOException {
        Path sigFile = Path.of(reportFile.toString() + ".sig");
        if (!Files.exists(sigFile)) {
            return "未找到签名文件 " + sigFile.getFileName() + "，无法校验";
        }
        String expected = Files.readString(sigFile, StandardCharsets.UTF_8)
                .lines()
                .filter(l -> l.startsWith("SHA-256:"))
                .map(l -> l.substring("SHA-256:".length()).trim())
                .findFirst()
                .orElse("");
        String actual = HashUtil.sha256OfFile(reportFile);
        if (expected.equalsIgnoreCase(actual)) {
            return "校验通过：报告内容完整，未被篡改（SHA-256 一致）";
        }
        return "校验失败：报告已被篡改！签名哈希 " + expected + "，实际哈希 " + actual;
    }

    private String buildHtml(List<HostInfo> hosts, List<AlertEvent> alerts, String rangeText) {
        long alive = hosts.stream().filter(HostInfo::isAlive).count();
        long totalOpenPorts = hosts.stream().mapToLong(h -> h.getOpenPorts().size()).sum();
        long critical = alerts.stream().filter(a -> a.getLevel() == AlertEvent.Level.CRITICAL).count();

        StringBuilder sb = new StringBuilder();
        sb.append("""
                <!DOCTYPE html>
                <html lang="zh-CN"><head><meta charset="UTF-8">
                <title>LanSentinel 扫描报告</title>
                <style>
                body{font-family:"Microsoft YaHei",sans-serif;margin:40px;color:#222}
                h1{border-bottom:3px solid #0FDC78;padding-bottom:8px}
                h2{margin-top:28px;border-left:4px solid #0FDC78;padding-left:10px}
                table{border-collapse:collapse;width:100%;margin-top:10px}
                th,td{border:1px solid #bbb;padding:8px;text-align:left;font-size:14px}
                th{background:#f0f0f0}
                .meta{color:#666;font-size:13px}
                .stat{display:inline-block;margin-right:30px;font-size:15px}
                .risk-high{color:#c0392b;font-weight:bold}
                .risk-mid{color:#d68910;font-weight:bold}
                .risk-low{color:#1e8449}
                .lv-CRITICAL{color:#c0392b;font-weight:bold}
                .lv-WARNING{color:#d68910;font-weight:bold}
                .lv-INFO{color:#2874a6}
                </style></head><body>
                """);
        sb.append("<h1>LanSentinel 局域网安全扫描报告</h1>");
        sb.append("<p class=\"meta\">生成时间：").append(LocalDateTime.now().format(FMT))
          .append("　授权网段：").append(rangeText).append("</p>");

        sb.append("<h2>一、扫描概览</h2>");
        sb.append("<p>")
          .append("<span class=\"stat\">扫描主机：<b>").append(hosts.size()).append("</b></span>")
          .append("<span class=\"stat\">在线主机：<b>").append(alive).append("</b></span>")
          .append("<span class=\"stat\">开放端口：<b>").append(totalOpenPorts).append("</b></span>")
          .append("<span class=\"stat\">高危告警：<b>").append(critical).append("</b></span>")
          .append("</p>");

        sb.append("<h2>二、主机与端口清单</h2><table>");
        sb.append("<tr><th>IP地址</th><th>状态</th><th>开放端口（Banner）</th><th>风险分</th><th>风险等级</th></tr>");
        for (HostInfo h : hosts) {
            sb.append("<tr><td>").append(h.getIp()).append("</td><td>")
              .append(h.isAlive() ? "在线" : "离线").append("</td><td>");
            if (h.isAlive()) {
                for (PortInfo p : h.getOpenPorts()) {
                    sb.append(p.getPort());
                    if (!p.getBanner().isEmpty()) {
                        sb.append("（").append(escape(p.getBanner())).append("）");
                    }
                    if (p.getConsistency() == PortInfo.Consistency.MISMATCH) {
                        sb.append(" <span class=\"risk-high\">[服务错位]</span>");
                    }
                    sb.append("<br>");
                }
            }
            sb.append("</td><td>").append(h.getRiskScore()).append("</td><td>")
              .append("<span class=\"").append(riskClass(h.getRiskScore())).append("\">")
              .append(riskLevel(h.getRiskScore())).append("</span></td></tr>");
        }
        sb.append("</table>");

        sb.append("<h2>三、安全告警汇总</h2>");
        if (alerts.isEmpty()) {
            sb.append("<p>本次扫描未产生告警。</p>");
        } else {
            sb.append("<table><tr><th>时间</th><th>级别</th><th>来源</th><th>描述</th></tr>");
            for (AlertEvent a : alerts) {
                sb.append("<tr><td>").append(a.getTime().format(FMT)).append("</td><td>")
                  .append("<span class=\"lv-").append(a.getLevel()).append("\">")
                  .append(a.getLevel()).append("</span></td><td>")
                  .append(a.getSource()).append("</td><td>").append(escape(a.getMessage()))
                  .append("</td></tr>");
            }
            sb.append("</table>");
        }
        sb.append("</body></html>");
        return sb.toString();
    }

    private String riskClass(int score) {
        if (score >= 60) {
            return "risk-high";
        }
        if (score >= 25) {
            return "risk-mid";
        }
        return "risk-low";
    }

    private String riskLevel(int score) {
        if (score >= 60) {
            return "高危";
        }
        if (score >= 25) {
            return "中危";
        }
        return "低危";
    }

    /** HTML特殊字符转义，防止Banner等外部数据破坏报告结构 */
    private String escape(String s) {
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
    }
}
