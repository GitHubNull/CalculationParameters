package burp;

import top.oxff.CalculationParameters;

/**
 * Burp Suite扩展入口点
 */
public class BurpExtender implements IBurpExtender {
    
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        // 设置扩展名称
        callbacks.setExtensionName("Calculation Parameters");
        
        // 初始化主扩展类
        CalculationParameters extension = new CalculationParameters(callbacks);
        
        // 注册为上下文菜单提供者
        callbacks.registerContextMenuFactory(extension);
        
        // 输出加载信息
        callbacks.printOutput("参数统计插件已加载！");
    }
} 