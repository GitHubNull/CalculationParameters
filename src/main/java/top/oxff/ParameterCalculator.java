package top.oxff;

import burp.BurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.IHttpRequestResponse;
import burp.IRequestInfo;

import top.oxff.utils.FormParameterProcessor;
import top.oxff.utils.GetParameterProcessor;
import top.oxff.utils.JsonParameterProcessor;
import top.oxff.utils.MultipartFormDataProcessor;
import top.oxff.utils.XmlParameterProcessor;

import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * 参数计算器类，用于计算HTTP请求中的参数数量
 */
public class ParameterCalculator {

    private final IBurpExtenderCallbacks callbacks;
    private final PrintWriter stdout;
    private final PrintWriter stderr;
    // 线程池，用于并行处理请求
    private ExecutorService threadPool;
    // 批处理大小
    private static final int BATCH_SIZE = 100;
    // 日志级别：0=详细，1=正常，2=最少
    private static final int LOG_LEVEL = 1;

    public ParameterCalculator(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.stdout = BurpExtender.getStdout();
        this.stderr = BurpExtender.getStderr();
        initThreadPool();
    }
    
    /**
     * 初始化线程池
     */
    private void initThreadPool() {
        // 创建线程池，线程数为处理器核心数，但最多16个线程
        int processors = Runtime.getRuntime().availableProcessors();
        int threadCount = Math.min(processors * 2, 16);
        this.threadPool = Executors.newFixedThreadPool(threadCount);
        if (LOG_LEVEL <= 1) {
            stdout.println("创建线程池，线程数: " + threadCount);
        }
    }

    /**
     * 处理请求列表，计算参数数量并更新备注
     * @param httpRequestResponses 要处理的请求响应数组
     */
    public void processRequests(IHttpRequestResponse[] httpRequestResponses) {
        if (httpRequestResponses == null || httpRequestResponses.length == 0) {
            stdout.println("没有请求");
            return;
        }
        
        // 如果请求数量太多，则需要关闭旧线程池创建新的
        if (httpRequestResponses.length > 500) {
            shutdownThreadPool();
            initThreadPool();
        }

        final AtomicInteger processedCount = new AtomicInteger(0);
        final AtomicInteger successCount = new AtomicInteger(0);
        
        // 记录开始时间
        long startTime = System.currentTimeMillis();
        stdout.println("开始处理 " + httpRequestResponses.length + " 个请求...");
        
        // 分批处理请求
        for (int batchStart = 0; batchStart < httpRequestResponses.length; batchStart += BATCH_SIZE) {
            int batchEnd = Math.min(batchStart + BATCH_SIZE, httpRequestResponses.length);
            int batchSize = batchEnd - batchStart;
            
            if (LOG_LEVEL <= 1) {
                stdout.println("处理批次 " + (batchStart / BATCH_SIZE + 1) + 
                      "，范围: " + (batchStart + 1) + "-" + batchEnd + 
                      "，共 " + batchSize + " 个请求");
            }
            
            final CountDownLatch batchLatch = new CountDownLatch(batchSize);
            
            // 提交当前批次的请求到线程池
            for (int i = batchStart; i < batchEnd; i++) {
                final IHttpRequestResponse requestResponse = httpRequestResponses[i];
                final int requestIndex = i;
                
                threadPool.submit(() -> {
                    try {
                        if (processRequest(requestResponse, requestIndex, httpRequestResponses.length)) {
                            successCount.incrementAndGet();
                        }
                        processedCount.incrementAndGet();
                        
                        // 每处理50个请求更新一次进度
                        int processed = processedCount.get();
                        if (processed % 50 == 0 || processed == httpRequestResponses.length) {
                            double percent = (double) processed / httpRequestResponses.length * 100;
                            final String progressMsg = String.format("进度: %.1f%% (%d/%d)", 
                                percent, processed, httpRequestResponses.length);
                            synchronized (stdout) {
                                stdout.println(progressMsg);
                            }
                        }
                    } catch (Exception e) {
                        synchronized (stderr) {
                            stderr.println("处理请求时发生错误: " + e.getMessage());
                        }
                    } finally {
                        batchLatch.countDown();
                    }
                });
            }
            
            try {
                // 等待当前批次完成，最多等待30秒
                boolean completed = batchLatch.await(30, TimeUnit.SECONDS);
                if (!completed) {
                    stderr.println("批次处理超时，继续下一批");
                }
            } catch (InterruptedException e) {
                stderr.println("等待批次完成时被中断: " + e.getMessage());
                Thread.currentThread().interrupt();
            }
            
            // 给UI线程喘息的机会
            try {
                Thread.sleep(100);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
        
        // 计算耗时
        long endTime = System.currentTimeMillis();
        double timeInSeconds = (endTime - startTime) / 1000.0;
        
        // 汇总处理结果
        stdout.println("处理完成! 共处理了 " + processedCount.get() + " 个请求，成功 " + 
                successCount.get() + " 个，耗时: " + timeInSeconds + " 秒");
    }
    
    /**
     * 关闭线程池
     */
    private void shutdownThreadPool() {
        if (threadPool != null && !threadPool.isShutdown()) {
            threadPool.shutdown();
            try {
                // 等待所有任务完成或超时
                if (!threadPool.awaitTermination(5, TimeUnit.SECONDS)) {
                    threadPool.shutdownNow();
                }
            } catch (InterruptedException e) {
                threadPool.shutdownNow();
                Thread.currentThread().interrupt();
            }
        }
    }
    
    /**
     * 处理单个请求
     * @param requestResponse 请求响应对象
     * @param index 请求在数组中的索引
     * @param total 总请求数
     * @return 是否成功处理
     */
    private boolean processRequest(IHttpRequestResponse requestResponse, int index, int total) {
        if (requestResponse == null) {
            if (LOG_LEVEL <= 1) {
                synchronized (stdout) {
                    stdout.println("请求为空 [" + (index + 1) + "/" + total + "]");
                }
            }
            return false;
        }

        byte[] requestBytes = requestResponse.getRequest();
        
        // 跳过null请求
        if (requestBytes == null || requestBytes.length == 0) {
            if (LOG_LEVEL <= 1) {
                synchronized (stdout) {
                    stdout.println("请求为空 [" + (index + 1) + "/" + total + "]");
                }
            }
            return false;
        }

        IRequestInfo requestInfo;

        try {
            requestInfo = callbacks.getHelpers().analyzeRequest(requestResponse);
        } catch (Exception e) {
            if (LOG_LEVEL <= 1) {
                synchronized (stderr) {
                    stderr.println("无法分析请求 [" + (index + 1) + "/" + total + "]: " + e.getMessage());
                }
            }
            return false;
        }

        if (requestInfo == null) {
            if (LOG_LEVEL <= 1) {
                synchronized (stdout) {
                    stdout.println("请求为空 [" + (index + 1) + "/" + total + "]");
                }
            }
            return false;
        }

        // 获取请求方法
        String method = requestInfo.getMethod();
        
        // 计算参数数量
        ParameterCounts counts;

        try {
            if (method.equals("GET") || method.equals("HEAD") || method.equals("OPTIONS")) {
                // GET请求使用专门的处理器处理URL参数
                counts = GetParameterProcessor.calculateGetParameters(requestInfo.getUrl());
            } else {
                // 对于POST等其他请求，继续处理请求体
                int bodyOffset = requestInfo.getBodyOffset();
                byte[] bodyBytes = Arrays.copyOfRange(requestBytes, bodyOffset, requestBytes.length);
                
                if (bodyBytes.length == 0) {
                    if (LOG_LEVEL <= 1) {
                        synchronized (stdout) {
                            stdout.println("请求体为空 [" + (index + 1) + "/" + total + "]");
                        }
                    }
                    return false;
                }
                
                counts = calculateParameterCounts(requestInfo, bodyBytes);
            }
        } catch (Exception e) {
            if (LOG_LEVEL <= 1) {
                synchronized (stderr) {
                    stderr.println("无法计算参数数量 [" + (index + 1) + "/" + total + "]: " + e.getMessage());
                }
            }
            return false;
        }

        if (counts == null) {
            if (LOG_LEVEL <= 1) {
                synchronized (stdout) {
                    stdout.println("无法计算参数数量 [" + (index + 1) + "/" + total + "]");
                }
            }
            return false;
        }

        
        // 更新请求备注
        String comment = String.format("赋值数量：%d / 参数数量：%d", counts.valuedCount, counts.totalCount);

        try {
            // 将统计结果添加到请求的备注中
            requestResponse.setComment(comment);
        } catch (Exception e) {
            if (LOG_LEVEL <= 1) {
                synchronized (stderr) {
                    stderr.println("无法更新请求备注 [" + (index + 1) + "/" + total + "]: " + e.getMessage());
                }
            }
            return false;
        }

        // 仅在详细日志级别输出详细信息
        if (LOG_LEVEL == 0) {
            synchronized (stdout) {
                stdout.println("------------------------------");
                stdout.println("URL: " + requestInfo.getUrl().toString());
                stdout.println("方法: " + method);
                stdout.println(comment);
                stdout.println("------------------------------");
            }
        }
            
        return true;
    }

    /**
     * 计算HTTP请求中的参数数量
     * @param requestInfo 请求信息
     * @param bodyBytes 请求体字节数组
     * @return 参数计数结果
     */
    private ParameterCounts calculateParameterCounts(IRequestInfo requestInfo, byte[] bodyBytes) {
        if (bodyBytes == null || bodyBytes.length == 0){
            return new ParameterCounts(0, 0);
        }

        // 获取请求体内容
        String bodyString;

        try {
            bodyString = new String(bodyBytes, StandardCharsets.UTF_8);
        } catch (Exception e) {
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