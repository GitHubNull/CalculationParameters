package top.oxff.utils;

import top.oxff.ParameterCounts;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 处理multipart/form-data格式参数的处理器
 */
public class MultipartFormDataProcessor {

    /**
     * 计算multipart/form-data参数数量
     * @param bodyString multipart/form-data格式的请求体字符串
     * @param contentType 请求的Content-Type头
     * @return 参数计数结果
     */
    public static ParameterCounts calculateMultipartParameters(String bodyString, String contentType) {
        int totalCount = 0;
        int valuedCount = 0;
        
        if (bodyString.trim().isEmpty()) {
            return new ParameterCounts(0, 0);
        }
        
        // 从Content-Type中提取boundary
        String boundary = extractBoundary(contentType);
        if (boundary == null) {
            return new ParameterCounts(0, 0);
        }
        
        // 解析各个部分
        List<String> parts = splitByBoundary(bodyString, boundary);
        totalCount = parts.size();
        
        // 分析每个部分是否有值
        for (String part : parts) {
            if (hasValue(part)) {
                valuedCount++;
            }
        }
        
        return new ParameterCounts(totalCount, valuedCount);
    }
    
    /**
     * 从Content-Type头中提取boundary值
     * @param contentType Content-Type头的值
     * @return boundary字符串，如果未找到则返回null
     */
    private static String extractBoundary(String contentType) {
        if (contentType == null) {
            return null;
        }
        
        Pattern pattern = Pattern.compile("boundary=([^;\\s]+)");
        Matcher matcher = pattern.matcher(contentType);
        if (matcher.find()) {
            return matcher.group(1);
        }
        
        return null;
    }
    
    /**
     * 按boundary分割请求体
     * @param bodyString 请求体字符串
     * @param boundary boundary字符串
     * @return 分割后的部分列表
     */
    private static List<String> splitByBoundary(String bodyString, String boundary) {
        List<String> result = new ArrayList<>();
        
        // 完整的boundary标记应该是"--{boundary}"
        String boundaryMarker = "--" + boundary;
        
        // 按boundary分割
        String[] parts = bodyString.split(Pattern.quote(boundaryMarker));
        
        // 第一部分通常是空的，最后一部分通常是结束分隔符，所以我们跳过它们
        for (int i = 1; i < parts.length; i++) {
            String part = parts[i];
            // 跳过结束分隔符
            if (part.trim().equals("--")) {
                continue;
            }
            // 去除开头的\r\n
            if (part.startsWith("\r\n")) {
                part = part.substring(2);
            }
            // 去除结尾的\r\n
            if (part.endsWith("\r\n")) {
                part = part.substring(0, part.length() - 2);
            }
            
            if (!part.trim().isEmpty()) {
                result.add(part);
            }
        }
        
        return result;
    }
    
    /**
     * 判断部分是否有值
     * @param part 部分字符串
     * @return 如果有值则返回true
     */
    private static boolean hasValue(String part) {
        // 分离头部和内容
        String[] headerAndContent = part.split("\r\n\r\n", 2);
        
        // 如果没有内容，则认为无值
        if (headerAndContent.length < 2) {
            return false;
        }
        
        String headers = headerAndContent[0];
        String content = headerAndContent[1];
        
        // 检查是否是文件上传
        if (isFileUpload(headers)) {
            // 对于文件上传，检查Content-Transfer-Encoding
            String transferEncoding = extractContentTransferEncoding(headers);
            
            // 检查是否有文件名
            boolean hasFilename = hasFilename(headers);
            
            // 如果是base64或binary编码，只需检查是否有文件名和内容长度大于0
            if ("base64".equalsIgnoreCase(transferEncoding) || "binary".equalsIgnoreCase(transferEncoding)) {
                return hasFilename && content.length() > 0;
            }
            
            // 对于其他编码类型或没有指定编码类型，检查是否有文件名和内容是否为空
            return hasFilename && !content.trim().isEmpty();
        }
        
        // 对于普通表单字段，如果内容不为空，则认为有值
        return !content.trim().isEmpty();
    }
    
    /**
     * 判断是否是文件上传
     * @param headers 部分的HTTP头
     * @return 如果是文件上传则返回true
     */
    private static boolean isFileUpload(String headers) {
        // 检查是否包含Content-Type头（文件上传通常会有）
        if (headers.contains("Content-Type:")) {
            return true;
        }
        
        // 检查是否在Content-Disposition中包含filename属性
        return hasFilename(headers);
    }
    
    /**
     * 判断是否包含filename属性
     * @param headers 部分的HTTP头
     * @return 如果包含filename属性则返回true
     */
    private static boolean hasFilename(String headers) {
        Pattern pattern = Pattern.compile("filename=\"([^\"]*)\"");
        Matcher matcher = pattern.matcher(headers);
        return matcher.find();
    }
    
    /**
     * 提取Content-Transfer-Encoding的值
     * @param headers 部分的HTTP头
     * @return Content-Transfer-Encoding的值，如果未找到则返回null
     */
    private static String extractContentTransferEncoding(String headers) {
        Pattern pattern = Pattern.compile("Content-Transfer-Encoding:\\s*([^\\r\\n]+)", Pattern.CASE_INSENSITIVE);
        Matcher matcher = pattern.matcher(headers);
        if (matcher.find()) {
            return matcher.group(1).trim();
        }
        return null;
    }
    
    /**
     * 从Content-Disposition中提取name值
     * @param headers 部分的HTTP头
     * @return name的值，如果未找到则返回null
     */
    private static String extractFieldName(String headers) {
        Pattern pattern = Pattern.compile("name=\"([^\"]+)\"");
        Matcher matcher = pattern.matcher(headers);
        if (matcher.find()) {
            return matcher.group(1);
        }
        return null;
    }
    
    /**
     * 从Content-Disposition中提取filename值
     * @param headers 部分的HTTP头
     * @return filename的值，如果未找到则返回null
     */
    private static String extractFilename(String headers) {
        Pattern pattern = Pattern.compile("filename=\"([^\"]*)\"");
        Matcher matcher = pattern.matcher(headers);
        if (matcher.find()) {
            return matcher.group(1);
        }
        return null;
    }
} 