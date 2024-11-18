package ru.symbolexec.SymbolicExec.controller;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import ru.symbolexec.SymbolicExec.core.ApkAnalyzer;
import ru.symbolexec.SymbolicExec.model.AnalysisReport;
import ru.symbolexec.SymbolicExec.util.FileHandler;

import java.io.File;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

@Controller
public class MainController {
    private final List<AnalysisReport> reports = new ArrayList<>();

    @GetMapping("/")
    public String index(Model model) {
        model.addAttribute("reports", reports); // Передача списка отчетов на главную страницу
        return "index";
    }

    @PostMapping("/upload")
    public String uploadFile(@RequestParam("file") MultipartFile file, Model model) {
        try {
            FileHandler fileHandler = new FileHandler();
            File apkFile = fileHandler.saveFile(file);

            ApkAnalyzer analyzer = new ApkAnalyzer();
            String reportPath = analyzer.analyzeApk(apkFile);

            // Добавляем отчет в список
            AnalysisReport report = new AnalysisReport(
                    reportPath,
                    LocalDateTime.now(),
                    apkFile.getName(),
                    "Success"
            );
            reports.add(report);

            model.addAttribute("message", "Analysis completed. Report saved at: " + reportPath);
        } catch (Exception e) {
            model.addAttribute("message", "Error: " + e.getMessage());

            // Добавляем отчет об ошибке
            AnalysisReport report = new AnalysisReport(
                    null,
                    LocalDateTime.now(),
                    file.getOriginalFilename(),
                    "Error"
            );
            reports.add(report);
        }
        return "index";
    }

    @GetMapping("/report")
    public String report(Model model) {
        model.addAttribute("reports", reports); // Передача списка отчетов на страницу отчетов
        return "report";
    }
}
