package ru.symbolexec.SymbolicExec.model;

import jakarta.persistence.*;

@Entity
@Table(name = "analysis_results")
public class AnalysisResult {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne
    @JoinColumn(name = "report_id", nullable = false)
    private AnalysisReport report;

    @Column(name = "grouped_details", columnDefinition = "TEXT", nullable = true)
    private String groupedDetails;

    public AnalysisResult() {}

    public AnalysisResult(AnalysisReport report, String groupedDetails) {
        this.report = report;
        this.groupedDetails = groupedDetails;
    }

    // Getters и Setters
    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public AnalysisReport getReport() {
        return report;
    }

    public void setReport(AnalysisReport report) {
        this.report = report;
    }

    public String getGroupedDetails() {
        return groupedDetails;
    }

    public void setGroupedDetails(String groupedDetails) {
        this.groupedDetails = groupedDetails;
    }
}
