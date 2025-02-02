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
import java.security.Principal;
import java.time.LocalDateTime;
import java.util.List;

@Controller
public class MainController {

    private final AnalysisReportRepository reportRepository;
    private final AnalysisResultRepository analysisResultRepository;
    private final UserService userService;

    @Autowired
    public MainController(AnalysisReportRepository reportRepository,
                          AnalysisResultRepository analysisResultRepository,
                          UserService userService) {
        this.reportRepository = reportRepository;
        this.analysisResultRepository = analysisResultRepository;
        this.userService = userService;
    }

    @GetMapping("/")
    public String index(@RequestParam(required = false) String message, Model model, Principal principal) {
        if (principal != null) {
            String username = principal.getName();
            User currentUser = userService.findByUsername(username);
            model.addAttribute("currentUser", currentUser);

            // Загрузка отчетов только для текущего пользователя
            List<AnalysisReport> reports = reportRepository.findByUser(currentUser);
            model.addAttribute("reports", reports);

            // Загрузка результатов анализа только для текущего пользователя
            List<AnalysisResult> results = analysisResultRepository.findByUser(currentUser);
            model.addAttribute("results", results);
        }

        model.addAttribute("message", message);

        return "index";
    }

    @PostMapping("/upload")
    public String uploadFile(@RequestParam("file") MultipartFile file, RedirectAttributes redirectAttributes, Principal principal) {
        try {
            if (principal == null) {
                redirectAttributes.addFlashAttribute("message", "Ошибка: пользователь не авторизован.");
                return "redirect:/";
            }

            FileHandler fileHandler = new FileHandler();
            File apkFile = fileHandler.saveFile(file);

            ApkAnalyzer analyzer = new ApkAnalyzer();
            AnalysisResultDto resultDto = analyzer.analyzeApk(apkFile);

            String username = principal.getName();
            User currentUser = userService.findByUsername(username);

            // Определение следующего userReportId для текущего пользователя
            AnalysisReport lastReport = reportRepository.findTopByUserOrderByUserReportIdDesc(currentUser);
            Long nextUserReportId = (lastReport != null) ? lastReport.getUserReportId() + 1 : 1;

            // Создаем отчет
            AnalysisReport report = new AnalysisReport(
                    resultDto.getReportPath(),
                    LocalDateTime.now(),
                    apkFile.getName(),
                    "Success"
            );

            report.setUser(currentUser);
            report.setUserReportId(nextUserReportId);

            reportRepository.save(report);

            // Создаем результат анализа
            AnalysisResult analysisResult = new AnalysisResult(report, resultDto.getGroupedDetails(), currentUser);
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
