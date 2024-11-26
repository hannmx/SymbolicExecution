package ru.symbolexec.SymbolicExec.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import ru.symbolexec.SymbolicExec.core.AnalysisResultDto;
import ru.symbolexec.SymbolicExec.core.ApkAnalyzer;
import ru.symbolexec.SymbolicExec.model.AnalysisReport;
import ru.symbolexec.SymbolicExec.model.AnalysisResult;
import ru.symbolexec.SymbolicExec.repository.AnalysisReportRepository;
import ru.symbolexec.SymbolicExec.repository.AnalysisResultRepository;
import ru.symbolexec.SymbolicExec.util.FileHandler;

import java.io.File;
import java.time.LocalDateTime;

@Controller
public class MainController {

    @Autowired
    private AnalysisReportRepository reportRepository;

    @Autowired
    private AnalysisResultRepository analysisResultRepository;

    @GetMapping("/")
    public String index(Model model) {
        model.addAttribute("reports", reportRepository.findAll());
        model.addAttribute("results", analysisResultRepository.findAll());
        model.addAttribute("message", "");
        return "index";
    }

    @PostMapping("/upload")
    public String uploadFile(@RequestParam("file") MultipartFile file, Model model) {
        try {
            FileHandler fileHandler = new FileHandler();
            File apkFile = fileHandler.saveFile(file);

            ApkAnalyzer analyzer = new ApkAnalyzer();
            AnalysisResultDto resultDto = analyzer.analyzeApk(apkFile);

            // Сохраняем отчет
            AnalysisReport report = new AnalysisReport(
                    resultDto.getReportPath(),
                    LocalDateTime.now(),
                    apkFile.getName(),
                    "Success"
            );
            reportRepository.save(report);

            // Сохраняем только группированные детали
            AnalysisResult analysisResult = new AnalysisResult(report.getId(), resultDto.getGroupedDetails());
            analysisResultRepository.save(analysisResult);

            model.addAttribute("message", "Анализ завершён. Отчет сохранен: " + resultDto.getReportPath());
            model.addAttribute("resultDetails", resultDto.getGroupedDetails()); // Показываем на главной
        } catch (Exception e) {
            model.addAttribute("message", "Ошибка: " + e.getMessage());
        }
        return "index";
    }

    @GetMapping("/report")
    public String getReport(Model model) {
        model.addAttribute("reports", reportRepository.findAll());
        return "report";
    }
}
