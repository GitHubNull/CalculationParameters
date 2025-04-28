package top.oxff.utils;

import top.oxff.ParameterCounts;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 处理multipart/form-data格式请求的处理器
 * 使用Apache HttpComponents的httpmime库提供的概念和数据结构
 */
public class MultipartFormDataProcessor {
    
    // 常量定义
    private static final Pattern BOUNDARY_PATTERN = Pattern.compile("boundary=(.+?)($|;|\\s)");
    private static final Pattern NAME_PATTERN = Pattern.compile("name=\"([^\"]+)\"");
    private static final Pattern FILENAME_PATTERN = Pattern.compile("filename=\"([^\"]+)\"");
    private static final byte[] CRLF = {'\r', '\n'};
    private static final byte[] DOUBLE_CRLF = {'\r', '\n', '\r', '\n'};
    
    /**
     * 计算multipart/form-data格式请求中的参数数量
     * @param bodyBytes 请求体字节数组
     * @param contentType Content-Type头值
     * @return 参数计数结果
     */
    public static ParameterCounts calculateMultipartParameters(byte[] bodyBytes, String contentType) {
        if (bodyBytes == null || contentType == null || !contentType.contains("multipart/form-data")) {
            return new ParameterCounts(0, 0);
        }
        
        try {
            // 从Content-Type中提取boundary
            String boundary = extractBoundary(contentType);
            if (boundary == null) {
                return new ParameterCounts(0, 0);
            }
            
            // 解析multipart/form-data数据
            List<FormPart> parts = parseMultipartData(bodyBytes, boundary);
            
            // 统计参数数量
            int totalCount = parts.size();
            int valuedCount = 0;
            
            for (FormPart part : parts) {
                if (part.hasValue()) {
                    valuedCount++;
                }
            }
            
            return new ParameterCounts(totalCount, valuedCount);
        } catch (Exception e) {
            // 解析失败时返回默认值
            return new ParameterCounts(0, 0);
        }
    }
    
    /**
     * 从Content-Type中提取boundary
     * @param contentType Content-Type头值
     * @return boundary字符串
     */
    private static String extractBoundary(String contentType) {
        Matcher matcher = BOUNDARY_PATTERN.matcher(contentType);
        if (matcher.find()) {
            return matcher.group(1);
        }
        return null;
    }
    
    /**
     * 解析multipart/form-data数据
     * @param bodyBytes 请求体字节数组
     * @param boundary 分隔符
     * @return 表单部分列表
     */
    private static List<FormPart> parseMultipartData(byte[] bodyBytes, String boundary) {
        List<FormPart> formParts = new ArrayList<>();
        String fullBoundary = "--" + boundary;
        byte[] boundaryBytes = fullBoundary.getBytes(StandardCharsets.UTF_8);
        
        // 查找所有boundary位置
        List<Integer> boundaryPositions = findSequencePositions(bodyBytes, boundaryBytes);
        
        for (int i = 0; i < boundaryPositions.size() - 1; i++) {
            int start = boundaryPositions.get(i) + boundaryBytes.length;
            int end = boundaryPositions.get(i + 1);
            
            // 跳过CRLF
            if (isSequenceAt(bodyBytes, start)) {
                start += CRLF.length;
            }
            
            // 查找头部和内容分隔位置
            int headerEnd = findSequence(bodyBytes, DOUBLE_CRLF, start, end);
            if (headerEnd != -1) {
                // 解析头部
                byte[] headerBytes = new byte[headerEnd - start];
                System.arraycopy(bodyBytes, start, headerBytes, 0, headerBytes.length);
                String headerString = new String(headerBytes, StandardCharsets.UTF_8);
                
                // 提取名称和文件名
                String name = extractValue(headerString, NAME_PATTERN);
                String filename = extractValue(headerString, FILENAME_PATTERN);
                
                // 提取内容
                int contentStart = headerEnd + DOUBLE_CRLF.length;
                int contentEnd = end;
                
                // 跳过内容末尾的CRLF（如果有）
                if (isSequenceAt(bodyBytes, contentEnd - CRLF.length)) {
                    contentEnd -= CRLF.length;
                }
                
                // 提取内容
                byte[] content = new byte[contentEnd - contentStart];
                System.arraycopy(bodyBytes, contentStart, content, 0, content.length);
                
                // 添加到表单部分列表
                formParts.add(new FormPart(name, filename, content));
            }
        }
        
        return formParts;
    }
    
    /**
     * 查找字节数组中指定序列的位置
     * @param data 数据字节数组
     * @param sequence 要查找的序列
     * @param start 开始位置
     * @param end 结束位置
     * @return 找到的位置，未找到返回-1
     */
    private static int findSequence(byte[] data, byte[] sequence, int start, int end) {
        end = Math.min(end, data.length);
        
        outer:
        for (int i = start; i <= end - sequence.length; i++) {
            for (int j = 0; j < sequence.length; j++) {
                if (data[i + j] != sequence[j]) {
                    continue outer;
                }
            }
            return i;
        }
        
        return -1;
    }
    
    /**
     * 查找字节数组中指定序列的所有位置
     * @param data 数据字节数组
     * @param sequence 要查找的序列
     * @return 位置列表
     */
    private static List<Integer> findSequencePositions(byte[] data, byte[] sequence) {
        List<Integer> positions = new ArrayList<>();
        
        int pos = 0;
        while (pos <= data.length - sequence.length) {
            int found = findSequence(data, sequence, pos, data.length);
            if (found == -1) {
                break;
            }
            positions.add(found);
            pos = found + sequence.length;
        }
        
        return positions;
    }
    
    /**
     * 检查字节数组指定位置是否匹配给定序列
     *
     * @param data     数据字节数组
     * @param position 位置
     * @return 是否匹配
     */
    private static boolean isSequenceAt(byte[] data, int position) {
        if (position < 0 || position + MultipartFormDataProcessor.CRLF.length > data.length) {
            return false;
        }
        
        for (int i = 0; i < MultipartFormDataProcessor.CRLF.length; i++) {
            if (data[position + i] != MultipartFormDataProcessor.CRLF[i]) {
                return false;
            }
        }
        
        return true;
    }
    
    /**
     * 从字符串中提取匹配模式的值
     * @param text 字符串
     * @param pattern 正则表达式模式
     * @return 提取的值，未找到返回null
     */
    private static String extractValue(String text, Pattern pattern) {
        Matcher matcher = pattern.matcher(text);
        if (matcher.find()) {
            return matcher.group(1);
        }
        return null;
    }
    
    /**
     * 表单部分类
     */
    private static class FormPart {
        private final String name;
        private final String filename;
        private final byte[] content;
        
        /**
         * 构造函数
         * @param name 字段名
         * @param filename 文件名
         * @param content 内容
         */
        public FormPart(String name, String filename, byte[] content) {
            this.name = name;
            this.filename = filename;
            this.content = content;
        }
        
        /**
         * 判断是否有值
         * @return 是否有值
         */
        public boolean hasValue() {
            // 文件上传部分始终视为有值
            if (filename != null && !filename.isEmpty()) {
                return true;
            }
            
            // 内容不为空视为有值
            return content != null && content.length > 0;
        }
    }
} 