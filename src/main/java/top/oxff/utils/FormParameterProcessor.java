package top.oxff.utils;

import top.oxff.ParameterCounts;

/**
 * 处理表单格式参数的处理器
 */
public class FormParameterProcessor {
    
    /**
     * 计算表单参数数量
     * @param bodyString 表单格式的请求体字符串
     * @return 参数计数结果
     */
    public static ParameterCounts calculateFormParameters(String bodyString) {
        int totalCount;
        int valuedCount = 0;
        
        if (bodyString.trim().isEmpty()) {
            return new ParameterCounts(0, 0);
        }
        
        // 解析表单参数
        String[] params = bodyString.split("&");
        totalCount = params.length;
        
        for (String param : params) {
            if (param.contains("=")) {
                String[] keyValue = param.split("=", 2);
                if (keyValue.length > 1 && !keyValue[1].isEmpty()) {
                    valuedCount++;
                }
            }
        }
        
        return new ParameterCounts(totalCount, valuedCount);
    }
} 