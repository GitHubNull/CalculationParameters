package top.oxff;

import burp.IContextMenuFactory;
import burp.IContextMenuInvocation;
import burp.IBurpExtenderCallbacks;
import burp.IHttpRequestResponse;

import javax.swing.*;
import java.util.ArrayList;
import java.util.List;

/**
 * 主扩展实现类，负责处理上下文菜单
 */
public class CalculationParameters implements IContextMenuFactory {

    private final IBurpExtenderCallbacks callbacks;
    private final ParameterCalculator calculator;

    public CalculationParameters(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.calculator = new ParameterCalculator(callbacks);
    }

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        // 只在代理历史记录中提供此功能
        if (invocation.getToolFlag() != IBurpExtenderCallbacks.TOOL_PROXY) {
            return null;
        }

        List<JMenuItem> menuItems = new ArrayList<>();
        JMenuItem calculateItem = new JMenuItem("计算参数量");
        
        calculateItem.addActionListener(e -> {
            // 获取用户选择的请求响应对象
            IHttpRequestResponse[] selectedMessages = invocation.getSelectedMessages();
            
            if (selectedMessages == null || selectedMessages.length == 0) {
                // 如果用户没有选择任何请求，则处理所有历史记录
                IHttpRequestResponse[] allHistory = callbacks.getProxyHistory();
                calculator.processRequests(allHistory);
                callbacks.printOutput("已处理所有历史请求，共 " + allHistory.length + " 个请求");
            } else {
                // 否则只处理选中的请求
                calculator.processRequests(selectedMessages);
                callbacks.printOutput("已处理选中的请求，共 " + selectedMessages.length + " 个请求");
            }
        });
        
        menuItems.add(calculateItem);
        return menuItems;
    }
} 