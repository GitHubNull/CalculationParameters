package top.oxff;

import java.util.Map;
import java.util.HashMap;

/**
 * 用于存储参数计数和详细参数信息的类。
 */
public class ParameterDetails {
    public final int valuedCount;
    public final int totalCount;
    public final Map<String, String> parameters;

    public ParameterDetails(int valuedCount, int totalCount, Map<String, String> parameters) {
        this.valuedCount = valuedCount;
        this.totalCount = totalCount;
        this.parameters = parameters != null ? new HashMap<>(parameters) : new HashMap<>();
    }

    // 提供一个空的构造函数或默认值，以防某些路径无法解析参数
    public static ParameterDetails empty() {
        return new ParameterDetails(0, 0, new HashMap<>());
    }
}