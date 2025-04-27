package top.oxff;

import top.oxff.utils.FormParameterProcessor;
import top.oxff.utils.JsonParameterProcessor;
import top.oxff.utils.MultipartFormDataProcessor;
import top.oxff.utils.XmlParameterProcessor;

/**
 * 处理通用格式参数的处理器
 */
public class GenericParameterProcessor {
    
    /**
     * 计算通用参数数量
     * @param bodyString 请求体字符串
     * @return 参数计数结果
     */
    public static ParameterCounts calculateGenericParameters(String bodyString) {
        int totalCount = 0;
        int valuedCount = 0;
        
        if (bodyString.trim().isEmpty()) {
            return new ParameterCounts(0, 0);
        }
        
        // 尝试检测常见的参数格式
        if (bodyString.contains("=") && bodyString.contains("&")) {
            // 可能是表单格式
            return FormParameterProcessor.calculateFormParameters(bodyString);
        } else if (bodyString.contains("\":") && bodyString.contains("{")) {
            // 可能是JSON格式
            return JsonParameterProcessor.calculateJsonParameters(bodyString);
        } else if (bodyString.contains("</") && bodyString.contains("<")) {
            // 可能是XML格式
            return XmlParameterProcessor.calculateXmlParameters(bodyString);
        } else if (bodyString.contains("Content-Disposition: form-data") && bodyString.contains("--")) {
            // 可能是multipart/form-data格式，需要模拟一个Content-Type头
            String fakeContentType = "multipart/form-data; boundary=---------------------------";
            return MultipartFormDataProcessor.calculateMultipartParameters(bodyString, fakeContentType);
        }
        
        // 如果无法确定格式，尝试按照通用方式计数
        int equalsCount = countOccurrences(bodyString, "=");
        totalCount = equalsCount;
        
        // 估计已赋值的参数数
        for (int i = 0; i < bodyString.length(); i++) {
            if (bodyString.charAt(i) == '=') {
                if (i < bodyString.length() - 1 && bodyString.charAt(i + 1) != '&' && bodyString.charAt(i + 1) != ' ') {
                    valuedCount++;
                }
            }
        }
        
        return new ParameterCounts(totalCount, valuedCount);
    }
    
    /**
     * 计算字符串中特定子串出现的次数
     * @param str 主字符串
     * @param target 目标子串
     * @return 出现次数
     */
    public static int countOccurrences(String str, String target) {
        int count = 0;
        int lastIndex = 0;
        
        while ((lastIndex = str.indexOf(target, lastIndex)) != -1) {
            count++;
            lastIndex += target.length();
        }
        
        return count;
    }
} 