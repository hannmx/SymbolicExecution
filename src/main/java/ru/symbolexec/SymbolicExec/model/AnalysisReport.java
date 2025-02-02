package ru.symbolexec.SymbolicExec.model;

import jakarta.persistence.*;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

@Entity
@Table(name = "analysis_reports")
public class AnalysisReport {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id; // Это глобальный ID, оставляем для технических нужд

    @Column(name = "user_report_id")
    private Long userReportId; // Новый ID для пользователя

    @Column(name = "report_path")
    private String reportPath;

    @Column(name = "analysis_date", nullable = false)
    private LocalDateTime analysisDate;

    @Column(name = "file_name", nullable = false)
    private String fileName;

    @Column(name = "status", nullable = false)
    private String status;

    @ManyToOne
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @OneToMany(mappedBy = "report", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<AnalysisResult> results = new ArrayList<>();

    public AnalysisReport() {}

    public AnalysisReport(String reportPath, LocalDateTime analysisDate, String fileName, String status) {
        this.reportPath = reportPath;
        this.analysisDate = analysisDate;
        this.fileName = fileName;
        this.status = status;
    }

    // Getters и Setters
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public Long getUserReportId() { return userReportId; }
    public void setUserReportId(Long userReportId) { this.userReportId = userReportId; }

    public String getReportPath() { return reportPath; }
    public void setReportPath(String reportPath) { this.reportPath = reportPath; }

    public LocalDateTime getAnalysisDate() { return analysisDate; }
    public void setAnalysisDate(LocalDateTime analysisDate) { this.analysisDate = analysisDate; }

    public String getFileName() { return fileName; }
    public void setFileName(String fileName) { this.fileName = fileName; }

    public String getStatus() { return status; }
    public void setStatus(String status) { this.status = status; }

    public User getUser() { return user; }
    public void setUser(User user) { this.user = user; }
}
