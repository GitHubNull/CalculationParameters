package top.oxff;

/**
 * 存储参数计数结果的类
 */
public class ParameterCounts {
    public final int totalCount;
    public final int valuedCount;

    public ParameterCounts(int totalCount, int valuedCount) {
        this.totalCount = totalCount;
        this.valuedCount = valuedCount;
    }
} 