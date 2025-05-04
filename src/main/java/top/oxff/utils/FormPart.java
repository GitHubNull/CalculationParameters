package top.oxff.utils;

import java.nio.charset.StandardCharsets;

/**
 * 表单部分类
 */
public class FormPart {
    private final String name;
    private final String filename;
    private final byte[] content;
    private final boolean isFile;

    /**
     * 构造函数
     * @param name 字段名
     * @param filename 文件名（如果是文件字段）
     * @param content 内容字节数组
     */
    public FormPart(String name, String filename, byte[] content) {
        this.name = name;
        this.filename = filename;
        this.content = content;
        this.isFile = filename != null && !filename.isEmpty();
    }

    /**
     * 获取字段名
     */
    public String getName() {
        return name;
    }

    /**
     * 是否是文件字段
     */
    public boolean isFile() {
        return isFile;
    }

    /**
     * 获取文件名（仅在 isFile 为 true 时有效）
     */
    public String getFilename() {
        return filename;
    }

    /**
     * 获取内容字节数组
     */
    public byte[] getContent() {
        return content;
    }

    /**
     * 获取文本字段的字符串值（仅在 isFile 为 false 且 content 非空时有效）
     */
    public String getTextValue() {
        if (isFile || content == null || content.length == 0) {
            return null;
        }
        return new String(content, StandardCharsets.UTF_8);
    }
}