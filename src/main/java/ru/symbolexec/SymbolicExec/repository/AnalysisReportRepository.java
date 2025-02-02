package ru.symbolexec.SymbolicExec.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import ru.symbolexec.SymbolicExec.model.AnalysisReport;
import ru.symbolexec.SymbolicExec.model.User;

import java.util.List;

public interface AnalysisReportRepository extends JpaRepository<AnalysisReport, Long> {
    List<AnalysisReport> findByUser(User user);
    AnalysisReport findTopByUserOrderByUserReportIdDesc(User user);
}
