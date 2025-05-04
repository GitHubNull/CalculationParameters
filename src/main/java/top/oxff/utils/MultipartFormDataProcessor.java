package top.oxff.utils;

import top.oxff.ParameterCounts;
import top.oxff.utils.FormPart;

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
    private static final String BOUNDARY_PREFIX = "boundary=";
    private static final String NAME_PREFIX = "name=\"";
    private static final String FILENAME_PREFIX = "filename=\"";
    private static final byte[] CRLF = new byte[] {(byte) '\r', (byte) '\n'};
    private static final byte[] DOUBLE_CRLF = new byte[] {(byte) '\r', (byte) '\n', (byte) '\r', (byte) '\n'};
    private static final int MAX_BOUNDARY_LENGTH = 70; // HTTP规范规定的最大boundary长度

    /**
     * 解析multipart/form-data数据并返回结构化结果
     * @param bodyBytes 请求体字节数组
     * @param contentType Content-Type头值
     * @return 结构化解析结果
     */
    public static MultipartResult processMultipartData(byte[] bodyBytes, String contentType) {
        if (bodyBytes == null || contentType == null || !contentType.contains("multipart/form-data")) {
            return new MultipartResult(new ArrayList<>());
        }

        try {
            String boundary = extractBoundary(contentType);
            if (boundary == null || boundary.length() > MAX_BOUNDARY_LENGTH) {
                boundary = attemptToExtractBoundaryFromData(bodyBytes);
            }
            
            if (boundary == null) {
                return new MultipartResult(new ArrayList<>());
            }
            
            List<FormPart> parts = parseMultipartData(bodyBytes, boundary);
            return new MultipartResult(parts);
        } catch (IllegalArgumentException | IllegalStateException e) {
            System.err.println("Error processing multipart form data: " + e.getMessage());
            return new MultipartResult(new ArrayList<>());
        } catch (Exception e) {
            // 捕获其他意外异常
            System.err.println("Unexpected error processing multipart form data: " + e.getMessage());
            return new MultipartResult(new ArrayList<>());
        }
    }
    
    /**
     * 计算multipart/form-data格式请求中的参数数量
     * @param bodyBytes 请求体字节数组
     * @param contentType Content-Type头值
     * @return 参数计数结果
     */
    public static ParameterCounts calculateMultipartParameters(byte[] bodyBytes, String contentType) {
        MultipartResult result = processMultipartData(bodyBytes, contentType);
        int totalCount = result.getAllParts().size();
        int valuedCount = (int) result.getAllParts().stream().filter(part -> part.getTextValue() != null).count();
        return new ParameterCounts(totalCount, valuedCount);
    }
    
    /**
     * 从Content-Type中提取boundary
     * @param contentType Content-Type头值
     * @return boundary字符串
     */
    private static String extractBoundary(String contentType) {
        int boundaryIndex = contentType.toLowerCase().indexOf(BOUNDARY_PREFIX.toLowerCase());
        if (boundaryIndex == -1) {
            return null;
        }
        
        int start = boundaryIndex + BOUNDARY_PREFIX.length();
        if (start >= contentType.length()) {
            return null;
        }
        
        char firstChar = contentType.charAt(start);
        if (firstChar == '"') {
            int end = contentType.indexOf('"', start + 1);
            if (end == -1) {
                end = contentType.length();
            }
            return contentType.substring(start + 1, end);
        } else {
            int end = contentType.length();
            for (int i = start; i < contentType.length(); i++) {
                char c = contentType.charAt(i);
                if (c == ';' || Character.isWhitespace(c)) {
                    end = i;
                    break;
                }
            }
            return contentType.substring(start, end).trim();
        }
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

        List<Integer> boundaryPositions = findSequencePositions(bodyBytes, boundaryBytes);

        for (int i = 0; i < boundaryPositions.size() - 1; i++) {
            int start = boundaryPositions.get(i) + boundaryBytes.length;
            int end = boundaryPositions.get(i + 1);

            if (isSequenceAt(bodyBytes, start)) {
                start += CRLF.length;
            }

            int headerEnd = findSequence(bodyBytes, DOUBLE_CRLF, start, end);
            if (headerEnd != -1) {
                byte[] headerBytes = extractBytes(bodyBytes, start, headerEnd - start);
                String headerString = new String(headerBytes, StandardCharsets.UTF_8);

                String name = extractValue(headerString, NAME_PREFIX);
                String filename = extractValue(headerString, FILENAME_PREFIX);

                int contentStart = headerEnd + DOUBLE_CRLF.length;
                int contentEnd = end;

                if (isSequenceAt(bodyBytes, contentEnd - CRLF.length)) {
                    contentEnd -= CRLF.length;
                }

                byte[] content = extractBytes(bodyBytes, contentStart, contentEnd - contentStart);

                formParts.add(new FormPart(name, filename, content));
            }
        }

        return formParts;
    }

    private static byte[] extractBytes(byte[] data, int start, int length) {
        byte[] result = new byte[length];
        System.arraycopy(data, start, result, 0, length);
        return result;
    }

    /**
     * 查找字节数组中指定序列的位置（使用Boyer-Moore算法优化）
     * @param data 数据字节数组
     * @param sequence 要查找的序列
     * @param start 开始位置
     * @param end 结束位置
     * @return 找到的位置，未找到返回-1
     */
    private static int findSequence(byte[] data, byte[] sequence, int start, int end) {
        if (sequence == null || null == data || sequence.length == 0 || data.length == 0 || start < 0 || end <= start || sequence.length > data.length - start) {
            return -1;
        }

        end = Math.min(end, data.length);
        
        // 构建坏字符规则表
        int[] badCharShift = new int[256];
        for (int i = 0; i < 256; i++) {
            badCharShift[i] = sequence.length;
        }
        for (int i = 0; i < sequence.length - 1; i++) {
            badCharShift[sequence[i] & 0xFF] = sequence.length - i - 1;
        }
        
        int pos = start;
        while (pos <= end - sequence.length) {
            int j = sequence.length - 1;
            while (j >= 0 && data[pos + j] == sequence[j]) {
                j--;
            }
            
            if (j < 0) {
                return pos;
            } else {
                // 使用坏字符规则移动
                pos += badCharShift[data[pos + sequence.length - 1] & 0xFF];
            }
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
     * @param data 数据字节数组
     * @param position 位置
     * @return 是否匹配
     */
    private static boolean isSequenceAt(byte[] data, int position) {
        if (data == null || position < 0 || position + CRLF.length > data.length || data.length - position < CRLF.length) {
            return false;
        }
        
        for (int i = 0; i < CRLF.length; i++) {
            if (data[position + i] != CRLF[i]) {
                return false;
            }
        }
        
        return true;
    }
    
    /**
     * 提取值
     * @param text 字符串
     * @param prefix 前缀
     * @return 提取的值，未找到返回null
     */
    private static String extractValue(String text, String prefix) {
        if (text == null || prefix == null) {
            return null;
        }
        
        int index = text.indexOf(prefix);
        if (index == -1) {
            return null;
        }
        
        int start = index + prefix.length();
        if (start >= text.length()) {
            return null;
        }
        
        int end = text.indexOf('"', start);
        if (end == -1) {
            end = text.length();
        }
        
        return text.substring(start, end);
    }

    /**
     * 尝试从请求体中提取boundary
     * @param bodyBytes 请求体字节数组
     * @return 提取的boundary值
     */
    private static String attemptToExtractBoundaryFromData(byte[] bodyBytes) {
        if (bodyBytes == null || bodyBytes.length < 2) {
            return null;
        }
        
        // 查找第一个换行符的位置
        int start = 0;
        while (start < bodyBytes.length - 1 && !(bodyBytes[start] == 13 && bodyBytes[start + 1] == 10)) {
            start++;
        }
        
        if (start >= bodyBytes.length - 1) {
            return null;
        }
        
        // 查找结束位置
        int end = start + 2;
        while (end < bodyBytes.length - 1 && !(bodyBytes[end] == '-' && bodyBytes[end + 1] == '-')) {
            end++;
        }
        
        if (end >= bodyBytes.length - 1) {
            return null;
        }
        
        // 提取boundary内容
        byte[] boundaryBytes = extractBytes(bodyBytes, start + 2, end - start - 2);
        if (boundaryBytes.length == 0) {
            return null;
        }
        
        return new String(boundaryBytes, StandardCharsets.UTF_8).trim();
    }
} 