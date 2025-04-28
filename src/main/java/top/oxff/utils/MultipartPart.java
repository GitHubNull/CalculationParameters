package top.oxff.utils;

/**
 * 表示multipart/form-data请求中的一个部分
 */
public class MultipartPart {
    // 头部开始位置
    final int headerStart;
    // 头部结束位置
    final int headerEnd;
    // 内容开始位置
    final int contentStart;
    // 内容结束位置
    final int contentEnd;
    
    /**
     * 构造函数
     * @param headerStart 头部开始位置
     * @param headerEnd 头部结束位置
     * @param contentStart 内容开始位置
     * @param contentEnd 内容结束位置
     */
    public MultipartPart(int headerStart, int headerEnd, int contentStart, int contentEnd) {
        this.headerStart = headerStart;
        this.headerEnd = headerEnd;
        this.contentStart = contentStart;
        this.contentEnd = contentEnd;
    }
    
    /**
     * 获取头部开始位置
     * @return 头部开始位置
     */
    public int getHeaderStart() {
        return headerStart;
    }
    
    /**
     * 获取头部结束位置
     * @return 头部结束位置
     */
    public int getHeaderEnd() {
        return headerEnd;
    }
    
    /**
     * 获取内容开始位置
     * @return 内容开始位置
     */
    public int getContentStart() {
        return contentStart;
    }
    
    /**
     * 获取内容结束位置
     * @return 内容结束位置
     */
    public int getContentEnd() {
        return contentEnd;
    }
} 