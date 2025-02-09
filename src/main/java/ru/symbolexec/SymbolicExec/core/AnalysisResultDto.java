package ru.symbolexec.SymbolicExec.core;

public class AnalysisResultDto {
    private String reportPath;
    private String fullReport;
    private String summaryDetails; // Добавляем краткий отчет

    public AnalysisResultDto(String reportPath, String fullReport, String summaryDetails) {
        this.reportPath = reportPath;
        this.fullReport = fullReport;
        this.summaryDetails = summaryDetails;
    }

    public String getFullReport() {
        return fullReport;
    }

    public void setReportPath(String reportPath) {
        this.reportPath = reportPath;
    }

    public void setFullReport(String fullReport) {
        this.fullReport = fullReport;
    }

    public void setSummaryDetails(String summaryDetails) {
        this.summaryDetails = summaryDetails;
    }

    public String getSummaryDetails() {
        return summaryDetails;
    }

    public String getReportPath() {
        return reportPath;
    }
}
