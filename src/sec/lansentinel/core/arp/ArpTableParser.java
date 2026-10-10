package sec.lansentinel.core.arp;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import sec.lansentinel.model.ArpEntry;

/**
 * ARP表解析器：执行系统 arp 命令并解析输出为 ArpEntry 列表。
 *
 * Windows 输出示例（中英文系统均兼容，只依赖IP+MAC的正则特征）：
 *   Interface: 192.168.1.10 --- 0xd
 *     192.168.1.1           aa-bb-cc-dd-ee-ff     dynamic
 */
public class ArpTableParser {

    /**
     * 匹配 "IP地址  MAC地址(短横线)  类型" 行。
     * 类型列在中文系统上是"动态/静态"，因此用 \\S+ 而非 \\w+（\\w 不匹配中文字符），
     * 同时类型列设为可选以增强兼容性。
     */
    private static final Pattern ENTRY_PATTERN = Pattern.compile(
            "(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})\\s+"
            + "([0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5})(?:\\s+(\\S+))?");

    /** 组播/广播MAC前缀，这类表项不参与欺骗检测 */
    private static final String IGNORE_PREFIX_01 = "01-00-5e";   // IPv4组播
    private static final String BROADCAST = "ff-ff-ff-ff-ff-ff";

    /** 执行 arp -a 并解析 */
    public List<ArpEntry> parse() throws IOException {
        Process process = new ProcessBuilder("arp", "-a").redirectErrorStream(true).start();
        List<ArpEntry> entries = new ArrayList<>();

        // arp命令跟随系统区域设置输出编码，GBK是中文Windows默认
        Charset charset = isChineseWindows()
                ? Charset.forName("GBK") : Charset.defaultCharset();
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream(), charset))) {
            String line;
            while ((line = reader.readLine()) != null) {
                Matcher m = ENTRY_PATTERN.matcher(line);
                if (m.find()) {
                    String type = m.group(3) == null ? "" : m.group(3);
                    ArpEntry entry = new ArpEntry(m.group(1), m.group(2), type);
                    if (!shouldIgnore(entry)) {
                        entries.add(entry);
                    }
                }
            }
        }
        return entries;
    }

    private boolean shouldIgnore(ArpEntry entry) {
        return entry.getMac().startsWith(IGNORE_PREFIX_01) || entry.getMac().equals(BROADCAST);
    }

    private boolean isChineseWindows() {
        return System.getProperty("os.name", "").toLowerCase().contains("win")
                && System.getProperty("user.language", "").equalsIgnoreCase("zh");
    }
}
