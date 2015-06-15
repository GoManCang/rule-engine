package com.ctrip.infosec.rule.convert.config;

import java.util.List;

/**
 * Created by yxjiang on 2015/6/15.
 */
public class InternalMappingConfigTree {
    private String path;
    private String sourcePath;
    private List<InternalMappingConfigTree> children;

    public String getPath() {
        return path;
    }

    public void setPath(String path) {
        this.path = path;
    }

    public String getSourcePath() {
        return sourcePath;
    }

    public void setSourcePath(String sourcePath) {
        this.sourcePath = sourcePath;
    }

    public List<InternalMappingConfigTree> getChildren() {
        return children;
    }

    public void setChildren(List<InternalMappingConfigTree> children) {
        this.children = children;
    }
}
