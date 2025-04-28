package top.oxff.utils;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
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
        if (jsonBody == null || jsonBody.trim().isEmpty()) {
            return new ParameterCounts(0, 0);
        }
        
        try {
            // 使用fastjson解析
            Object jsonObj = JSON.parse(jsonBody);
            
            // 递归计算参数
            ParameterCounter counter = new ParameterCounter();
            countParameters(jsonObj, counter);
            
            return new ParameterCounts(counter.totalCount, counter.valuedCount);
        } catch (Exception e) {
            // 解析失败时返回默认值
            return new ParameterCounts(0, 0);
        }
    }
    
    /**
     * 递归计算JSON参数数量
     * @param jsonObj JSON对象
     * @param counter 计数器
     */
    private static void countParameters(Object jsonObj, ParameterCounter counter) {
        if (jsonObj == null) {
            return;
        }
        
        if (jsonObj instanceof JSONObject) {
            JSONObject jsonObject = (JSONObject) jsonObj;
            
            for (String key : jsonObject.keySet()) {
                Object value = jsonObject.get(key);
                counter.totalCount++;
                
                if (isValuedParameter(value)) {
                    counter.valuedCount++;
                }
                
                // 递归处理嵌套对象
                if (value instanceof JSONObject || value instanceof JSONArray) {
                    countParameters(value, counter);
                }
            }
        } else if (jsonObj instanceof JSONArray) {
            JSONArray jsonArray = (JSONArray) jsonObj;
            
            for (int i = 0; i < jsonArray.size(); i++) {
                Object item = jsonArray.get(i);
                
                // 递归处理数组项
                if (item instanceof JSONObject || item instanceof JSONArray) {
                    countParameters(item, counter);
                }
            }
        }
    }
    
    /**
     * 判断参数是否有值
     * @param value 参数值
     * @return 是否有值
     */
    private static boolean isValuedParameter(Object value) {
        if (value == null) {
            return false;
        }
        
        if (value instanceof String) {
            return !((String) value).isEmpty();
        }
        
        if (value instanceof JSONArray) {
            return !((JSONArray) value).isEmpty();
        }
        
        if (value instanceof JSONObject) {
            return !((JSONObject) value).isEmpty();
        }
        
        // 数字、布尔等其他类型视为有值
        return true;
    }
    
    /**
     * 参数计数器
     */
    private static class ParameterCounter {
        int totalCount = 0;
        int valuedCount = 0;
    }
} 