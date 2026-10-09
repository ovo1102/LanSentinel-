package sec.lansentinel.service;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Properties;
import java.util.Set;

/**
 * 配置管理器：加载 config.properties，向各模块提供配置项。
 */
public class ConfigManager {

    private final Properties props = new Properties();

    public ConfigManager(Path configFile) throws IOException {
        try (InputStream in = Files.newInputStream(configFile)) {
            props.load(in);
        }
    }

    public String get(String key) {
        String value = props.getProperty(key);
        if (value == null) {
            throw new IllegalStateException("缺少配置项: " + key);
        }
        return value.trim();
    }

    public String get(String key, String defaultValue) {
        return props.getProperty(key, defaultValue).trim();
    }

    public int getInt(String key, int defaultValue) {
        String value = props.getProperty(key);
        if (value == null) {
            return defaultValue;
        }
        return Integer.parseInt(value.trim());
    }

    /** 读取逗号分隔的整数列表，如端口列表 "21,22,80" */
    public int[] getIntList(String key) {
        return Arrays.stream(get(key).split(","))
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .mapToInt(Integer::parseInt)
                .toArray();
    }

    /** 读取逗号分隔的整数集合（用于高危端口知识库的O(1)查找） */
    public Set<Integer> getIntSet(String key) {
        Set<Integer> set = new HashSet<>();
        for (int v : getIntList(key)) {
            set.add(v);
        }
        return set;
    }
}
