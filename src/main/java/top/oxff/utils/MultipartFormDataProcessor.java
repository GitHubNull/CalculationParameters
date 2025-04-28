package top.oxff.utils;

import top.oxff.ParameterCounts;

import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 处理multipart/form-data格式请求的处理器
 */
public class MultipartFormDataProcessor {
    // 分隔符常量
    private static final byte[] CRLF = new byte[] {'\r', '\n'};
    private static final byte[] DOUBLE_CRLF = new byte[] {'\r', '\n', '\r', '\n'};
    private static final String CONTENT_DISPOSITION = "Content-Disposition:";
    private static final String FORM_DATA = "form-data";
    private static final String FILENAME = "filename";
    
    /**
     * 计算multipart/form-data格式请求中的参数数量
     * @param bodyBytes 请求体字节数组
     * @param contentType Content-Type头值
     * @return 参数计数结果
     */
    public static ParameterCounts calculateMultipartParameters(byte[] bodyBytes, String contentType) {
        try {
            // 从Content-Type中提取boundary
            String boundary = extractBoundary(contentType);
            if (boundary == null || bodyBytes == null) {
                return new ParameterCounts(0, 0);
            }
            
            return calculateMultipartParametersByBytes(bodyBytes, boundary);
        } catch (Exception e) {
            // 发生异常时返回默认值
            return new ParameterCounts(0, 0);
        }
    }
    
    /**
     * 使用字节数组方式计算multipart/form-data格式请求中的参数数量
     * @param bodyBytes 请求体字节数组
     * @param boundary 分隔符
     * @return 参数计数结果
     */
    private static ParameterCounts calculateMultipartParametersByBytes(byte[] bodyBytes, String boundary) {
        byte[] boundaryBytes = ("--" + boundary).getBytes();
        List<MultipartPart> parts = findParts(bodyBytes, boundaryBytes);
        
        int totalCount = 0;
        int valuedCount = 0;
        
        for (MultipartPart part : parts) {
            totalCount++;

            // 提取部分头信息
            byte[] headerBytes = Arrays.copyOfRange(bodyBytes, part.getHeaderStart(), part.getHeaderEnd());
            String headers = new String(headerBytes, StandardCharsets.UTF_8);

            // 只处理form-data部分
            if (!headers.contains(FORM_DATA)) {
                continue;
            }

            // 检查内容是否为空
            byte[] contentBytes = Arrays.copyOfRange(bodyBytes, part.getContentStart(), part.getContentEnd());
            boolean isEmpty = contentBytes.length == 0;

            // 检查是否为文件上传
            boolean isFile = headers.contains(FILENAME);

            // 文件上传或非空内容计为有值参数
            if (isFile || !isEmpty) {
                valuedCount++;
            }
        }
        
        return new ParameterCounts(totalCount, valuedCount);
    }
    
    /**
     * 从Content-Type中提取boundary
     * @param contentType Content-Type头值
     * @return boundary字符串
     */
    private static String extractBoundary(String contentType) {
        if (contentType == null || !contentType.contains("multipart/form-data")) {
            return null;
        }
        
        Pattern pattern = Pattern.compile("boundary=(.+?)($|;|\\s)");
        Matcher matcher = pattern.matcher(contentType);
        
        if (matcher.find()) {
            return matcher.group(1);
        }
        
        return null;
    }
    
    /**
     * 在字节数组中查找所有部分
     * @param data 请求体字节数组
     * @param boundary 分隔符字节数组
     * @return 部分列表
     */
    private static List<MultipartPart> findParts(byte[] data, byte[] boundary) {
        List<MultipartPart> parts = new ArrayList<>();
        List<Integer> boundaryPositions = findAllOccurrences(data, boundary);
        
        for (int i = 0; i < boundaryPositions.size() - 1; i++) {
            int start = boundaryPositions.get(i) + boundary.length;
            int end = boundaryPositions.get(i + 1);
            
            // 跳过CRLF
            if (start < data.length && data[start] == '\r' && start + 1 < data.length && data[start + 1] == '\n') {
                start += 2;
            }
            
            // 查找头部和内容分隔位置
            int headerEnd = findSequence(data, DOUBLE_CRLF, start, end);
            if (headerEnd != -1) {
                int contentStart = headerEnd + DOUBLE_CRLF.length;
                int contentEnd = end;
                
                // 跳过内容末尾的CRLF（如果有）
                if (contentEnd > 2 && data[contentEnd - 2] == '\r' && data[contentEnd - 1] == '\n') {
                    contentEnd -= 2;
                }
                
                parts.add(new MultipartPart(start, headerEnd, contentStart, contentEnd));
            }
        }
        
        return parts;
    }
    
    /**
     * 查找字节序列在数据中的位置
     * @param data 数据字节数组
     * @param sequence 要查找的序列
     * @param start 开始位置
     * @param end 结束位置
     * @return 找到的位置或-1
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
     * 查找所有指定字节序列的位置
     * @param data 数据字节数组
     * @param sequence 要查找的序列
     * @return 位置列表
     */
    private static List<Integer> findAllOccurrences(byte[] data, byte[] sequence) {
        List<Integer> positions = new ArrayList<>();
        
        outer:
        for (int i = 0; i <= data.length - sequence.length; i++) {
            for (int j = 0; j < sequence.length; j++) {
                if (data[i + j] != sequence[j]) {
                    continue outer;
                }
            }
            positions.add(i);
        }
        
        return positions;
    }
} 