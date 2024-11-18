package ru.symbolexec.SymbolicExec.model;

import java.time.LocalDateTime;

public class AnalysisReport {
    private String reportPath;
    private LocalDateTime analysisDate;
    private String apkName;
    private String status; // e.g., "Success", "Error"

    public AnalysisReport(String reportPath, LocalDateTime analysisDate, String apkName, String status) {
        this.reportPath = reportPath;
        this.analysisDate = analysisDate;
        this.apkName = apkName;
        this.status = status;
    }

    public String getReportPath() {
        return reportPath;
    }

    public LocalDateTime getAnalysisDate() {
        return analysisDate;
    }

    public String getApkName() {
        return apkName;
    }

    public String getStatus() {
        return status;
    }

    public void setReportPath(String reportPath) {
        this.reportPath = reportPath;
    }

    public void setAnalysisDate(LocalDateTime analysisDate) {
        this.analysisDate = analysisDate;
    }

    public void setApkName(String apkName) {
        this.apkName = apkName;
    }

    public void setStatus(String status) {
        this.status = status;
    }
}
