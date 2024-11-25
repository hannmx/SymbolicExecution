package ru.symbolexec.SymbolicExec.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import ru.symbolexec.SymbolicExec.model.AnalysisResult;

public interface AnalysisResultRepository extends JpaRepository<AnalysisResult, Long> {
}
