package top.oxff.utils;

import org.dom4j.Document;
import org.dom4j.DocumentException;
import org.dom4j.DocumentHelper;
import org.dom4j.Element;
import org.dom4j.Node;
import top.oxff.ParameterCounts;

import java.util.Iterator;
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
        if (xmlBody == null || xmlBody.trim().isEmpty()) {
            return new ParameterCounts(0, 0);
        }
        
        try {
            // 使用DOM4J解析XML
            Document document = DocumentHelper.parseText(xmlBody);
            Element rootElement = document.getRootElement();
            
            // 递归计算参数
            ParameterCounter counter = new ParameterCounter();
            processElement(rootElement, counter);
            
            return new ParameterCounts(counter.totalCount, counter.valuedCount);
        } catch (DocumentException e) {
            // 解析失败时返回默认值
            return new ParameterCounts(0, 0);
        }
    }
    
    /**
     * 递归处理XML元素
     * @param element XML元素
     * @param counter 计数器
     */
    private static void processElement(Element element, ParameterCounter counter) {
        // 处理属性
        for (Iterator<org.dom4j.Attribute> it = element.attributeIterator(); it.hasNext();) {
            org.dom4j.Attribute attribute = it.next();
            counter.totalCount++;
            
            // 属性非空视为有值
            if (attribute.getValue() != null && !attribute.getValue().trim().isEmpty()) {
                counter.valuedCount++;
            }
        }
        
        // 处理子元素
        List<Node> nodes = element.content();
        boolean hasValuedContent = false;
        
        for (Node node : nodes) {
            if (node instanceof Element) {
                // 子元素递归处理
                processElement((Element) node, counter);
            } else if (node.getNodeType() == Node.TEXT_NODE) {
                // 文本节点非空视为有值
                String text = node.getText().trim();
                if (!text.isEmpty()) {
                    hasValuedContent = true;
                }
            }
        }
        
        // 如果元素没有子元素但有属性，则视为一个参数
        if (element.elements().isEmpty()) {
            counter.totalCount++;
            if (hasValuedContent) {
                counter.valuedCount++;
            }
        }
    }
    
    /**
     * 参数计数器
     */
    private static class ParameterCounter {
        int totalCount = 0;
        int valuedCount = 0;
    }
} 