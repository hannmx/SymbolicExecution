package ru.symbolexec.SymbolicExec.model;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

public class AnalysisReport {
    private String reportPath;
    private LocalDateTime analysisDate;
    private String apkName;
    private String status;
    private List<String> vulnerabilities = new ArrayList<>();

    public AnalysisReport(String reportPath, LocalDateTime analysisDate, String apkName, String status) {
        this.reportPath = reportPath;
        this.analysisDate = analysisDate;
        this.apkName = apkName;
        this.status = status;
    }

    // Геттеры и сеттеры
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

    public List<String> getVulnerabilities() {
        return vulnerabilities;
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

    public void setVulnerabilities(List<String> vulnerabilities) {
        this.vulnerabilities = vulnerabilities;
    }

    public void addVulnerability(String vulnerability) {
        this.vulnerabilities.add(vulnerability);
    }

    public String toString() {
        return "Report for APK: " + apkName +
                "\nStatus: " + status +
                "\nAnalysis Date: " + analysisDate +
                "\nVulnerabilities: " + vulnerabilities +
                "\nReport Path: " + reportPath;
    }
}
