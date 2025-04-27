package top.oxff.utils;

import top.oxff.ParameterCounts;

/**
 * 处理JSON格式参数的处理器
 */
public class JsonParameterProcessor {
    
    /**
     * 计算JSON参数数量
     * @param jsonBody JSON格式的请求体字符串
     * @return 参数计数结果
     */
    public static ParameterCounts calculateJsonParameters(String jsonBody) {
        int totalCount = 0;
        int valuedCount = 0;
        
        if (jsonBody.trim().isEmpty()) {
            return new ParameterCounts(0, 0);
        }
        
        // 计数键值对
        int keyValuePairs = countJSONKeyValuePairs(jsonBody);
        totalCount = keyValuePairs;
        
        // 计数非空值
        int nonEmptyValues = countJSONNonEmptyValues(jsonBody);
        valuedCount = nonEmptyValues;
        
        return new ParameterCounts(totalCount, valuedCount);
    }
    
    /**
     * 计算JSON中键值对的数量
     * @param jsonBody JSON字符串
     * @return 键值对数量
     */
    private static int countJSONKeyValuePairs(String jsonBody) {
        // 简单计数JSON中的键值对数量
        // 计算 "key": 模式的出现次数
        int count = 0;
        int index = 0;
        
        while ((index = jsonBody.indexOf("\":", index)) != -1) {
            count++;
            index += 2;
        }
        
        return count;
    }
    
    /**
     * 计算JSON中非空值的数量
     * @param jsonBody JSON字符串
     * @return 非空值数量
     */
    private static int countJSONNonEmptyValues(String jsonBody) {
        // 简单计数JSON中非空值的数量
        // 这里我们假设非空值是不等于 null, "", [], {} 的值
        int count = 0;
        int index = 0;
        
        while ((index = jsonBody.indexOf("\":", index)) != -1) {
            index += 2;
            
            // 跳过空白字符
            while (index < jsonBody.length() && Character.isWhitespace(jsonBody.charAt(index))) {
                index++;
            }
            
            if (index < jsonBody.length()) {
                char nextChar = jsonBody.charAt(index);
                
                // 检查是否是空值
                if (nextChar == 'n' && index + 4 <= jsonBody.length() && jsonBody.substring(index, index + 4).equals("null")) {
                    // 空值，不计数
                } else if (nextChar == '\"' && index + 2 <= jsonBody.length() && jsonBody.charAt(index + 1) == '\"') {
                    // 空字符串，不计数
                } else if (nextChar == '[' && index + 2 <= jsonBody.length() && jsonBody.charAt(index + 1) == ']') {
                    // 空数组，不计数
                } else if (nextChar == '{' && index + 2 <= jsonBody.length() && jsonBody.charAt(index + 1) == '}') {
                    // 空对象，不计数
                } else {
                    // 非空值，计数加一
                    count++;
                }
            }
            
            index++;
        }
        
        return count;
    }
} 