package sec.lansentinel.service;

import sec.lansentinel.util.IpUtil;

/**
 * 授权守卫：安全工具的伦理设计。
 *
 * 扫描器是一把双刃剑，本类强制约束所有扫描行为只能发生在
 * 课程授权网段（172.20.85 ~ 172.20.104）内，任何越界目标一律拒绝。
 */
public class AuthGuard {

    private final long rangeStart;
    private final long rangeEnd;
    private final String rangeText;

    public AuthGuard(ConfigManager config) {
        String start = config.get("auth.range.start");
        String end = config.get("auth.range.end");
        // 支持课程分配表的缩写形式（172.20.85 -> 172.20.85.0）
        this.rangeStart = IpUtil.boundaryToLong(start, true);
        this.rangeEnd = IpUtil.boundaryToLong(end, false);
        this.rangeText = start + " ~ " + end;
    }

    /**
     * 校验目标IP是否在授权范围内，越界则抛出异常拒绝执行。
     *
     * @throws SecurityException 目标不在授权网段时抛出
     */
    public void checkTarget(String ip) {
        long target = IpUtil.ipToLong(ip);   // 格式非法时同样抛异常
        if (target < rangeStart || target > rangeEnd) {
            throw new SecurityException(
                "[拒绝] 目标 " + ip + " 不在授权范围 " + rangeText + " 内。\n"
                + "本工具仅允许在授权范围内使用，请遵守网络安全法相关规定。");
        }
    }

    /** 静默校验：返回是否授权，不抛异常（供GUI前置判断使用） */
    public boolean isAuthorized(String ip) {
        try {
            checkTarget(ip);
            return true;
        } catch (SecurityException | IllegalArgumentException e) {
            return false;
        }
    }

    public String getRangeText() {
        return rangeText;
    }
}
