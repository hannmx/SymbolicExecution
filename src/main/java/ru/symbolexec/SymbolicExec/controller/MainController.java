package ru.symbolexec.SymbolicExec.controller;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import ru.symbolexec.SymbolicExec.core.ApkAnalyzer;
import ru.symbolexec.SymbolicExec.model.AnalysisReport;
import ru.symbolexec.SymbolicExec.util.FileHandler;

import java.io.File;
import java.text.SimpleDateFormat;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

@Controller
public class MainController {
    private final List<AnalysisReport> reports = new ArrayList<>();

    @GetMapping("/")
    public String index(Model model) {
        model.addAttribute("reports", reports); // Список отчётов
        model.addAttribute("message", ""); // Пустое сообщение при загрузке страницы
        return "index";
    }

    @PostMapping("/upload")
    public String uploadFile(@RequestParam("file") MultipartFile file, Model model) {
        try {
            FileHandler fileHandler = new FileHandler();
            File apkFile = fileHandler.saveFile(file);

            ApkAnalyzer analyzer = new ApkAnalyzer();
            String reportPath = analyzer.analyzeApk(apkFile);

            // Успешный анализ
            AnalysisReport report = new AnalysisReport(
                    reportPath,
                    LocalDateTime.now(),
                    apkFile.getName(),
                    "Success"
            );
            reports.add(report);

            model.addAttribute("message", "Анализ завершён. Отчет сохранен: " + reportPath);
        } catch (Exception e) {
            model.addAttribute("message", "Ошибка: " + e.getMessage());

            // Добавляем отчёт об ошибке
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
    public String getReport(Model model) {
        String formattedDate = new SimpleDateFormat("yyyy-MM-dd HH:mm").format(new Date());
        model.addAttribute("formattedDate", formattedDate);
        return "report";
    }
}

