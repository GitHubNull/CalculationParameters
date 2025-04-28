package burp;

import top.oxff.CalculationParameters;

import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;

/**
 * Burp Suite扩展入口点
 */
public class BurpExtender implements IBurpExtender, IExtensionStateListener {
    public static final String EXTENSION_NAME = "Calculation Parameters";
    public static final String VERSION = "1.0.0";
    public static IBurpExtenderCallbacks callbacks;
    public static IExtensionHelpers helpers;
    private static PrintWriter stdout;
    private static PrintWriter stderr;

    public static IBurpExtenderCallbacks getCallbacks() {
        return callbacks;
    }

    public static IExtensionHelpers getHelpers() {
        return helpers;
    }

    public static PrintWriter getStdout() {
        return stdout;
    }

    public static PrintWriter getStderr() {
        return stderr;
    }

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        BurpExtender.callbacks = callbacks;

        BurpExtender.helpers = callbacks.getHelpers();

        // 设置扩展名称
        callbacks.setExtensionName(EXTENSION_NAME + " v" + VERSION);

        // 设置标准输出和错误输出使用UTF-8编码（兼容低版本JDK）
        OutputStream stdoutStream = callbacks.getStdout();
        OutputStream stderrStream = callbacks.getStderr();
        stdout = new PrintWriter(new OutputStreamWriter(stdoutStream, StandardCharsets.UTF_8), true);
        stderr = new PrintWriter(new OutputStreamWriter(stderrStream, StandardCharsets.UTF_8), true);

        // 注册扩展状态监听器
        callbacks.registerExtensionStateListener(this);

        // 初始化主扩展类
        CalculationParameters extension = new CalculationParameters(callbacks);

        // 注册为上下文菜单提供者
        callbacks.registerContextMenuFactory(extension);

        // 输出加载信息
        stdout.println("参数统计插件已加载！");
        stdout.println("插件支持中文！测试中文输出...");
    }

    @Override
    public void extensionUnloaded() {
        if (stdout != null) {
            stdout.println("参数统计插件已卸载！");
        }
    }
}
