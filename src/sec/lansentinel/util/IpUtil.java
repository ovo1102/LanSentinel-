package sec.lansentinel.util;

import java.util.ArrayList;
import java.util.List;

/**
 * IP工具类：IP与long互转、网段展开、范围校验。
 * 课程指定网段 172.20.85 ~ 172.20.104 的展开与校验都依赖本类。
 */
public final class IpUtil {

    private IpUtil() {
    }

    /** 将点分十进制IP转为long，便于范围比较。非法格式抛出 IllegalArgumentException */
    public static long ipToLong(String ip) {
        String[] parts = ip.trim().split("\\.");
        if (parts.length != 4) {
            throw new IllegalArgumentException("非法IP格式: " + ip);
        }
        long result = 0;
        for (String part : parts) {
            int num;
            try {
                num = Integer.parseInt(part);
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException("非法IP格式: " + ip);
            }
            if (num < 0 || num > 255) {
                throw new IllegalArgumentException("IP字段越界: " + ip);
            }
            result = (result << 8) | num;
        }
        return result;
    }

    /**
     * 规范化网段边界IP。
     * 课程分配表使用缩写形式（如 "172.20.85" 表示 172.20.85.x 整段），
     * 起点不足4段补0，终点不足4段补255。
     * 例：start="172.20.85" -> 172.20.85.0；end="172.20.104" -> 172.20.104.255
     */
    public static long boundaryToLong(String ip, boolean isStart) {
        String trimmed = ip.trim();
        int dots = trimmed.length() - trimmed.replace(".", "").length();
        StringBuilder sb = new StringBuilder(trimmed);
        for (int i = dots; i < 3; i++) {
            sb.append(isStart ? ".0" : ".255");
        }
        return ipToLong(sb.toString());
    }

    /** 将long转回点分十进制IP */
    public static String longToIp(long value) {
        return ((value >> 24) & 0xFF) + "." +
               ((value >> 16) & 0xFF) + "." +
               ((value >> 8) & 0xFF) + "." +
               (value & 0xFF);
    }

    /** 判断IP是否落在 [start, end] 范围内（闭区间） */
    public static boolean isInRange(String ip, String start, String end) {
        long target = ipToLong(ip);
        return target >= ipToLong(start) && target <= ipToLong(end);
    }

    /** 展开 [start, end] 范围内的所有IP地址 */
    public static List<String> expandRange(String start, String end) {
        long s = ipToLong(start);
        long e = ipToLong(end);
        if (s > e) {
            throw new IllegalArgumentException("IP段起点大于终点: " + start + " ~ " + end);
        }
        List<String> list = new ArrayList<>();
        for (long i = s; i <= e; i++) {
            list.add(longToIp(i));
        }
        return list;
    }
}
