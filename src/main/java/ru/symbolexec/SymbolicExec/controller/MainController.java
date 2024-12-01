package ru.symbolexec.SymbolicExec.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;
import ru.symbolexec.SymbolicExec.core.AnalysisResultDto;
import ru.symbolexec.SymbolicExec.core.ApkAnalyzer;
import ru.symbolexec.SymbolicExec.model.AnalysisReport;
import ru.symbolexec.SymbolicExec.model.AnalysisResult;
import ru.symbolexec.SymbolicExec.repository.AnalysisReportRepository;
import ru.symbolexec.SymbolicExec.repository.AnalysisResultRepository;
import ru.symbolexec.SymbolicExec.util.FileHandler;

import java.io.File;
import java.time.LocalDateTime;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

@Controller
public class MainController {

    @Autowired
    private AnalysisReportRepository reportRepository;

    @Autowired
    private AnalysisResultRepository analysisResultRepository;

    @GetMapping("/")
    public String index(@RequestParam(required = false) String message, Model model) {
        // Проверяем, если отчеты и результаты не были добавлены в модель, то добавляем их
        if (!model.containsAttribute("reports")) {
            model.addAttribute("reports", reportRepository.findAll());
        }
        if (!model.containsAttribute("results")) {
            model.addAttribute("results", analysisResultRepository.findAll());
        }

        // Добавляем сообщение об успешном завершении анализа, если оно есть
        if (message != null) {
            model.addAttribute("message", message);
        }

        return "index";
    }

    @PostMapping("/upload")
    public String uploadFile(@RequestParam("file") MultipartFile file, RedirectAttributes redirectAttributes) {
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

            // Перенаправляем с сообщением и результатами
            redirectAttributes.addFlashAttribute("message", "Анализ завершён. Отчет сохранен: " + resultDto.getReportPath());
            redirectAttributes.addFlashAttribute("resultDetails", resultDto.getGroupedDetails());

            // Возвращаем перенаправление на главную страницу с параметром message
            return "redirect:/?message=" + URLEncoder.encode("Анализ завершён. Отчет сохранен: " + resultDto.getReportPath(), StandardCharsets.UTF_8);
        } catch (Exception e) {
            // Добавляем сообщение об ошибке
            redirectAttributes.addFlashAttribute("message", "Ошибка: " + e.getMessage());
            return "redirect:/";
        }
    }

    @GetMapping("/report")
    public String getReport(Model model) {
        model.addAttribute("reports", reportRepository.findAll());
        return "report";
    }
}
