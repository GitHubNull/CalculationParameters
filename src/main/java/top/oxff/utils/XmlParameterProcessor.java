package top.oxff.utils;

import top.oxff.ParameterCounts;

import java.util.ArrayList;
import java.util.List;

/**
 * 处理XML格式参数的处理器
 */
public class XmlParameterProcessor {
    
    /**
     * 计算XML参数数量
     * @param xmlBody XML格式的请求体字符串
     * @return 参数计数结果
     */
    public static ParameterCounts calculateXmlParameters(String xmlBody) {
        int totalCount;
        int valuedCount = 0;
        
        if (xmlBody.trim().isEmpty()) {
            return new ParameterCounts(0, 0);
        }
        
        // 计数XML标签数量
        List<String> tags = extractXmlTags(xmlBody);
        totalCount = tags.size();
        
        // 计数非空XML标签数量
        for (String tag : tags) {
            if (!tag.isEmpty()) {
                valuedCount++;
            }
        }
        
        return new ParameterCounts(totalCount, valuedCount);
    }

    /**
     * 提取XML标签及其内容
     * @param xmlBody XML字符串
     * @return 标签内容列表
     */
    private static List<String> extractXmlTags(String xmlBody) {
        List<String> tags = new ArrayList<>();
        int startIndex = 0;
        
        while (startIndex < xmlBody.length()) {
            int openTagStart = xmlBody.indexOf("<", startIndex);
            if (openTagStart == -1) break;
            
            int openTagEnd = xmlBody.indexOf(">", openTagStart);
            if (openTagEnd == -1) break;
            
            String tagName = extractTagName(xmlBody.substring(openTagStart + 1, openTagEnd));
            
            // 检查是否是自闭合标签
            if (xmlBody.charAt(openTagEnd - 1) == '/' || tagName.startsWith("?")) {
                startIndex = openTagEnd + 1;
                continue;
            }
            
            // 查找对应的关闭标签
            String closeTag = "</" + tagName + ">";
            int closeTagStart = xmlBody.indexOf(closeTag, openTagEnd);
            
            if (closeTagStart != -1) {
                // 提取标签内容
                String content = xmlBody.substring(openTagEnd + 1, closeTagStart).trim();
                tags.add(content);
                startIndex = closeTagStart + closeTag.length();
            } else {
                startIndex = openTagEnd + 1;
            }
        }
        
        return tags;
    }
    
    /**
     * 提取标签名
     * @param tag 标签字符串
     * @return 标签名
     */
    private static String extractTagName(String tag) {
        // 从标签中提取标签名
        int spaceIndex = tag.indexOf(" ");
        if (spaceIndex != -1) {
            return tag.substring(0, spaceIndex);
        }
        return tag;
    }
} 