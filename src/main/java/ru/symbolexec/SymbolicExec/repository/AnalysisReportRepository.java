package ru.symbolexec.SymbolicExec.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import ru.symbolexec.SymbolicExec.model.AnalysisReport;

public interface AnalysisReportRepository extends JpaRepository<AnalysisReport, Long> {
}
