package ru.symbolexec.SymbolicExec.model;

import jakarta.persistence.*;

@Entity
@Table(name = "analysis_results")
public class AnalysisResult {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "report_id", nullable = false)
    private Long reportId; // Связь с AnalysisReport

    @Column(name = "details", columnDefinition = "TEXT", nullable = false)
    private String details; // Подробности анализа

    public AnalysisResult() {}

    public AnalysisResult(Long reportId, String details) {
        this.reportId = reportId;
        this.details = details;
    }

    // Getters и Setters
    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public Long getReportId() {
        return reportId;
    }

    public void setReportId(Long reportId) {
        this.reportId = reportId;
    }

    public String getDetails() {
        return details;
    }

    public void setDetails(String details) {
        this.details = details;
    }
}
