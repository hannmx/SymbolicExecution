package ru.symbolexec.SymbolicExec.core;

import java.util.Map;

public class AnalysisResultDto {
    private String reportPath;
    private String details;

    public AnalysisResultDto(String reportPath, String details) {
        this.reportPath = reportPath;
        this.details = details;
    }

    public String getReportPath() {
        return reportPath;
    }

    public String getDetails() {
        return details;
    }
}
