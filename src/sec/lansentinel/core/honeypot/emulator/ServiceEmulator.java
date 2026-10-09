package sec.lansentinel.core.honeypot.emulator;

import java.io.IOException;
import java.net.Socket;

/**
 * 协议伪装接口：蜜罐不实现真实服务，只模拟服务的"开场白"，
 * 诱使攻击者暴露行为数据（低交互蜜罐设计，避免蜜罐本身被攻陷利用）。
 */
public interface ServiceEmulator {

    /** 伪装协议名，用于日志记录，如 "TELNET" */
    String protocol();

    /**
     * 与攻击者进行一次伪装交互。
     *
     * @return 捕获到的行为数据（如账号密码、客户端指纹）
     */
    String emulate(Socket socket) throws IOException;
}
