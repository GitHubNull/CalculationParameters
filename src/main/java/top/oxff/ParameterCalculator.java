package top.oxff;

import burp.IBurpExtenderCallbacks;
import burp.IHttpRequestResponse;
import burp.IRequestInfo;

import top.oxff.utils.FormParameterProcessor;
import top.oxff.utils.JsonParameterProcessor;
import top.oxff.utils.MultipartFormDataProcessor;
import top.oxff.utils.XmlParameterProcessor;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * 参数计算器类，用于计算HTTP请求中的参数数量
 */
public class ParameterCalculator {

    private final IBurpExtenderCallbacks callbacks;

    public ParameterCalculator(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
    }

    /**
     * 处理请求列表，计算参数数量并更新备注
     * @param httpRequestResponses 要处理的请求响应数组
     */
    public void processRequests(IHttpRequestResponse[] httpRequestResponses) {
        if (httpRequestResponses == null || httpRequestResponses.length == 0){
            callbacks.printOutput("没有请求");
            return;
        }

        int processedCount = 0;
        
        for (IHttpRequestResponse requestResponse : httpRequestResponses) {
            if (requestResponse == null){
                callbacks.printOutput("请求为空");
                continue;
            }

            byte[] requestBytes = requestResponse.getRequest();
            
            // 跳过null请求
            if (requestBytes == null || requestBytes.length == 0) {
                callbacks.printOutput("请求为空");
                continue;
            }

            IRequestInfo requestInfo;

            try {
                requestInfo = callbacks.getHelpers().analyzeRequest(requestResponse);
            }catch (Exception e){
                callbacks.printError("无法分析请求：" + e.getMessage());
                continue;
            }

            if (requestInfo == null){
                callbacks.printOutput("请求为空");
                continue;
            }

            // 获取请求方法
            String method = requestInfo.getMethod();
            if (method.equals("GET") || method.equals("HEAD") || method.equals("OPTIONS")) {
                callbacks.printOutput("GET/HEAD/OPTIONS请求不支持");
                continue;
            }
            
            // 只处理包含请求体的请求
            int bodyOffset = requestInfo.getBodyOffset();
            byte[] bodyBytes = Arrays.copyOfRange(requestBytes, bodyOffset, requestBytes.length);
            
            if (bodyBytes.length == 0) {
                callbacks.printOutput("请求体为空");
                continue;
            }

            // 计算参数数量
            ParameterCounts counts;

            try {
                counts = calculateParameterCounts(requestInfo, bodyBytes);
            }catch (Exception e){
                callbacks.printError("无法计算参数数量：" + e.getMessage());
                continue;
            }

            if (counts == null){
                callbacks.printOutput("无法计算参数数量");
                continue;
            }

            
            // 更新请求备注
            String comment = String.format("赋值数量：%d / 参数数量：%d", counts.valuedCount, counts.totalCount);

            try {
                // 将统计结果添加到请求的备注中
                requestResponse.setComment(comment);
            }catch (Exception e){
                callbacks.printError("无法更新请求备注：" + e.getMessage());
                continue;
            }

            // 输出日志
            callbacks.printOutput("------------------------------");
            callbacks.printOutput("URL: " + requestInfo.getUrl().toString());
            callbacks.printOutput(comment);
            callbacks.printOutput("------------------------------");
            
            processedCount++;
        }
        
        // 汇总处理结果
        callbacks.printOutput("共处理了 " + processedCount + " 个请求");
    }

    /**
     * 计算HTTP请求中的参数数量
     * @param requestInfo 请求信息
     * @param bodyBytes 请求体字节数组
     * @return 参数计数结果
     */
    private ParameterCounts calculateParameterCounts(IRequestInfo requestInfo, byte[] bodyBytes) {
        if (bodyBytes == null || bodyBytes.length == 0){
            callbacks.printOutput("请求体为空");
            return new ParameterCounts(0, 0);
        }

        // 获取请求体内容
        String bodyString;

        try {
            bodyString = new String(bodyBytes, StandardCharsets.UTF_8);
        } catch (Exception e) {
            callbacks.printOutput("无法解析请求体");
            return new ParameterCounts(0, 0);
        }

        if (bodyString.trim().isEmpty()){
            return new ParameterCounts(0, 0);
        }

        // 获取Content-Type头
        Map<String, String> headers = getRequestHeaders(requestInfo);
        String contentType = headers.get("content-type");
        
        if (contentType != null) {
            if (contentType.contains("application/json")) {
                // 处理JSON请求体
                return JsonParameterProcessor.calculateJsonParameters(bodyString);
            } else if (contentType.contains("application/x-www-form-urlencoded")) {
                // 处理表单提交
                return FormParameterProcessor.calculateFormParameters(bodyString);
            } else if (contentType.contains("multipart/form-data")) {
                // 处理multipart/form-data格式请求，直接使用字节数组
                return MultipartFormDataProcessor.calculateMultipartParameters(bodyBytes, contentType);
            } else if (contentType.contains("application/xml") || contentType.contains("text/xml")) {
                // 处理XML请求
                return XmlParameterProcessor.calculateXmlParameters(bodyString);
            } else {
                // 对于其他格式，尝试通用方法
                return GenericParameterProcessor.calculateGenericParameters(bodyBytes);
            }
        } else {
            // 无Content-Type头，尝试通用方法
            return GenericParameterProcessor.calculateGenericParameters(bodyBytes);
        }
    }
    
    /**
     * 解析请求头
     * @param requestInfo 请求信息
     * @return 请求头键值对映射
     */
    private Map<String, String> getRequestHeaders(IRequestInfo requestInfo) {
        Map<String, String> headerMap = new HashMap<>();
        List<String> headers = requestInfo.getHeaders();
        
        // 跳过第一行（HTTP请求行）
        for (int i = 1; i < headers.size(); i++) {
            String header = headers.get(i);
            int colonIndex = header.indexOf(":");
            if (colonIndex > 0) {
                String name = header.substring(0, colonIndex).trim().toLowerCase();
                String value = header.substring(colonIndex + 1).trim();
                headerMap.put(name, value);
            }
        }
        
        return headerMap;
    }
} 