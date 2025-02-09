package ru.symbolexec.SymbolicExec.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.Resource;
import org.springframework.core.io.UrlResource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
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
import java.io.PrintWriter;
import java.net.MalformedURLException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.Principal;
import java.time.LocalDateTime;
import java.util.Arrays;
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

            // Определение следующего userReportId
            AnalysisReport lastReport = reportRepository.findTopByUserOrderByUserReportIdDesc(currentUser);
            Long nextUserReportId = (lastReport != null) ? lastReport.getUserReportId() + 1 : 1;

            // Полный отчет в текстовый файл
            String reportPath = "reports/report_" + nextUserReportId + ".txt";
            File fullReportFile = new File(reportPath);
            try (PrintWriter writer = new PrintWriter(fullReportFile)) {
                writer.println("Отчет по анализу APK: " + apkFile.getName());
                writer.println("Дата анализа: " + LocalDateTime.now());
                writer.println("--------------------------------");
                writer.println(resultDto.getFullReport()); // Полный отчет
            }

            // Создаем отчет
            AnalysisReport report = new AnalysisReport(
                    reportPath, LocalDateTime.now(), apkFile.getName(), "Success"
            );
            report.setUser(currentUser);
            report.setUserReportId(nextUserReportId);
            reportRepository.save(report);

            // Краткий отчет
            String summary = extractSummary(resultDto.getSummaryDetails());

            // Создаем результат анализа (в БД хранится краткая версия)
            AnalysisResult analysisResult = new AnalysisResult(report, summary, currentUser);
            analysisResultRepository.save(analysisResult);

            redirectAttributes.addFlashAttribute("message", "Анализ завершён. Отчет доступен для скачивания.");
            return "redirect:/";
        } catch (Exception e) {
            redirectAttributes.addFlashAttribute("message", "Ошибка: " + e.getMessage());
            return "redirect:/";
        }
    }

    // Функция извлекает краткую версию отчета
    private String extractSummary(String fullReport) {
        String[] lines = fullReport.split("\n");
        return String.join("\n", Arrays.copyOfRange(lines, 0, Math.min(5, lines.length)));
    }

    @GetMapping("/report")
    public String getReport(Model model, Principal principal) {
        if (principal != null) {
            String username = principal.getName();
            User currentUser = userService.findByUsername(username);

            // Загружаем только отчеты текущего пользователя
            List<AnalysisReport> userReports = reportRepository.findByUser(currentUser);
            model.addAttribute("reports", userReports);
        }
        return "report";
    }

    @GetMapping("/download/{id}")
    public ResponseEntity<Resource> downloadReport(@PathVariable Long id, Principal principal) {
        AnalysisReport report = reportRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("Отчет не найден"));

        // Проверяем, принадлежит ли отчет текущему пользователю
        User currentUser = userService.findByUsername(principal.getName());
        if (!report.getUser().equals(currentUser)) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).build(); // Запрет доступа к чужим отчетам
        }

        try {
            Path filePath = Paths.get(report.getReportPath());
            Resource resource = new UrlResource(filePath.toUri());

            if (resource.exists() && resource.isReadable()) {
                return ResponseEntity.ok()
                        .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + filePath.getFileName() + "\"")
                        .body(resource);
            } else {
                throw new RuntimeException("Файл не найден или недоступен для чтения.");
            }
        } catch (MalformedURLException e) {
            throw new RuntimeException("Ошибка при чтении файла: " + e.getMessage());
        }
    }

}
