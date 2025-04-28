package top.oxff.utils;

import top.oxff.ParameterCounts;

import java.net.URL;
import java.util.HashMap;
import java.util.Map;

/**
 * 处理GET请求URL参数的处理器
 */
public class GetParameterProcessor {
    
    /**
     * 计算GET请求URL中的参数数量
     * @param url 请求URL
     * @return 参数计数结果
     */
    public static ParameterCounts calculateGetParameters(URL url) {
        if (url == null) {
            return new ParameterCounts(0, 0);
        }
        
        String query = url.getQuery();
        if (query == null || query.trim().isEmpty()) {
            return new ParameterCounts(0, 0);
        }
        
        // 解析查询参数
        Map<String, String> parameters = parseQueryString(query);
        
        int totalCount = parameters.size();
        int valuedCount = 0;
        
        // 计算有赋值的参数数量
        for (Map.Entry<String, String> entry : parameters.entrySet()) {
            String value = entry.getValue();
            if (value != null && !value.trim().isEmpty()) {
                valuedCount++;
            }
        }
        
        return new ParameterCounts(totalCount, valuedCount);
    }
    
    /**
     * 解析URL查询字符串
     * @param query 查询字符串
     * @return 参数映射
     */
    private static Map<String, String> parseQueryString(String query) {
        Map<String, String> parameters = new HashMap<>();
        
        if (query == null || query.trim().isEmpty()) {
            return parameters;
        }
        
        String[] pairs = query.split("&");
        for (String pair : pairs) {
            int idx = pair.indexOf("=");
            if (idx > 0) {
                String key = pair.substring(0, idx);
                String value = (idx < pair.length() - 1) ? pair.substring(idx + 1) : "";
                parameters.put(key, value);
            } else {
                // 没有等号的参数视为只有键没有值
                parameters.put(pair, "");
            }
        }
        
        return parameters;
    }
} 