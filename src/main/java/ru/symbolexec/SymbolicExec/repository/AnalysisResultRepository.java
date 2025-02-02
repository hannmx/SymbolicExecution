package ru.symbolexec.SymbolicExec.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import ru.symbolexec.SymbolicExec.model.AnalysisReport;
import ru.symbolexec.SymbolicExec.model.AnalysisResult;
import ru.symbolexec.SymbolicExec.model.User;

import java.util.List;

public interface AnalysisResultRepository extends JpaRepository<AnalysisResult, Long> {
    List<AnalysisResult> findByUser(User user);
}
