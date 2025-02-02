package ru.symbolexec.SymbolicExec.model;

import jakarta.persistence.*;

@Entity
@Table(name = "analysis_results")
public class AnalysisResult {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @ManyToOne
    @JoinColumn(name = "report_id", nullable = false)
    private AnalysisReport report;

    @Column(name = "grouped_details", columnDefinition = "TEXT", nullable = true)
    private String groupedDetails;

    public AnalysisResult() {}


    public AnalysisResult(AnalysisReport report, String groupedDetails, User user) {
        this.report = report;
        this.groupedDetails = groupedDetails;
        this.user = user;
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
    public User getUser() {
        return user;
    }
    public void setUser(User user) {
        this.user = user;
    }
}
