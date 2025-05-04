package top.oxff.utils;

import java.util.ArrayList;
import java.util.List;

/**
 * 封装 multipart/form-data 解析结果
 */
public class MultipartResult {
    private final List<FormPart> allParts;
    private final List<FormPart> fileParts;
    private final List<FormPart> textParts;

    public MultipartResult(List<FormPart> parts) {
        this.allParts = new ArrayList<>(parts);
        this.fileParts = new ArrayList<>();
        this.textParts = new ArrayList<>();

        for (FormPart part : parts) {
            if (part.isFile()) {
                fileParts.add(part);
            } else {
                textParts.add(part);
            }
        }
    }

    /**
     * 获取所有字段
     */
    public List<FormPart> getAllParts() {
        return allParts;
    }

    /**
     * 获取文件字段列表
     */
    public List<FormPart> getFileParts() {
        return fileParts;
    }

    /**
     * 获取文本字段列表
     */
    public List<FormPart> getTextParts() {
        return textParts;
    }

    /**
     * 根据字段名获取文本字段值
     * @param name 字段名
     * @return 文本值，不存在或非文本字段返回 null
     */
    public String getFirstTextValue(String name) {
        return textParts.stream()
                .filter(part -> name.equals(part.getName()))
                .map(FormPart::getTextValue)
                .findFirst()
                .orElse(null);
    }

    /**
     * 判断是否包含指定名称的文件字段
     * @param name 文件字段名
     * @return 是否存在
     */
    public boolean containsFilePart(String name) {
        return fileParts.stream().anyMatch(part -> name.equals(part.getName()));
    }
}