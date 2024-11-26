package ru.symbolexec.SymbolicExec.core;

public class AnalysisResultDto {
    private String reportPath;
    private String groupedDetails;

    public AnalysisResultDto(String reportPath, String groupedDetails) {
        this.reportPath = reportPath;
        this.groupedDetails = groupedDetails;
    }

    public String getGroupedDetails() {
        return groupedDetails;
    }

    public String getReportPath() {
        return reportPath;
    }
}
