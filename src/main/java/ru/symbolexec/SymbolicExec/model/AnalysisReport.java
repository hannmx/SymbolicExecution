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
