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
import ru.symbolexec.SymbolicExec.model.User;
import ru.symbolexec.SymbolicExec.repository.AnalysisReportRepository;
import ru.symbolexec.SymbolicExec.repository.AnalysisResultRepository;
import ru.symbolexec.SymbolicExec.service.UserService;
import ru.symbolexec.SymbolicExec.util.FileHandler;

import java.io.File;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.Principal;
import java.time.LocalDateTime;

@Controller
public class MainController {

    @Autowired
    private AnalysisReportRepository reportRepository;

    @Autowired
    private AnalysisResultRepository analysisResultRepository;

    @Autowired
    private UserService userService;

    @GetMapping("/")
    public String index(@RequestParam(required = false) String message, Model model, Principal principal) {
        if (principal == null) {
            return "redirect:/login";
        }

        String username = principal.getName();
        User currentUser = userService.findByUsername(username);

        model.addAttribute("reports", reportRepository.findAll());
        model.addAttribute("results", analysisResultRepository.findAll());
        model.addAttribute("message", message);

        return "index";
    }

    @PostMapping("/upload")
    public String uploadFile(@RequestParam("file") MultipartFile file, RedirectAttributes redirectAttributes) {
        try {
            FileHandler fileHandler = new FileHandler();
            File apkFile = fileHandler.saveFile(file);

            ApkAnalyzer analyzer = new ApkAnalyzer();
            AnalysisResultDto resultDto = analyzer.analyzeApk(apkFile);

            AnalysisReport report = new AnalysisReport(
                    resultDto.getReportPath(),
                    LocalDateTime.now(),
                    apkFile.getName(),
                    "Success"
            );
            reportRepository.save(report);

            AnalysisResult analysisResult = new AnalysisResult(report, resultDto.getGroupedDetails());
            analysisResultRepository.save(analysisResult);

            redirectAttributes.addFlashAttribute("message", "Анализ завершён. Отчет сохранен: " + resultDto.getReportPath());
            return "redirect:/";
        } catch (Exception e) {
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
