package sec.lansentinel.util;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * 哈希工具类：计算SHA-256，用于报告文件的完整性保护（M4报告防篡改使用）。
 */
public final class HashUtil {

    private HashUtil() {
    }

    /** 计算文件内容的SHA-256，返回小写十六进制字符串 */
    public static String sha256OfFile(Path file) throws IOException {
        MessageDigest digest = newDigest();
        try (InputStream in = Files.newInputStream(file)) {
            byte[] buf = new byte[8192];
            int len;
            while ((len = in.read(buf)) != -1) {
                digest.update(buf, 0, len);
            }
        }
        return toHex(digest.digest());
    }

    /** 计算字符串的SHA-256 */
    public static String sha256OfString(String text) {
        MessageDigest digest = newDigest();
        return toHex(digest.digest(text.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
    }

    private static MessageDigest newDigest() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            // SHA-256 是Java标准必含算法，不会到达这里
            throw new IllegalStateException(e);
        }
    }

    private static String toHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(Character.forDigit((b >> 4) & 0xF, 16));
            sb.append(Character.forDigit(b & 0xF, 16));
        }
        return sb.toString();
    }
}
