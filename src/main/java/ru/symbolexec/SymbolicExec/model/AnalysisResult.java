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

    @Column(name = "grouped_details", columnDefinition = "TEXT", nullable = true)
    private String groupedDetails; // Для хранения группированного отчета

    public AnalysisResult() {}

    public AnalysisResult(Long reportId, String groupedDetails) {
        this.reportId = reportId;
        this.groupedDetails = groupedDetails;
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

    public String getGroupedDetails() {
        return groupedDetails;
    }

    public void setGroupedDetails(String groupedDetails) {
        this.groupedDetails = groupedDetails;
    }
}
