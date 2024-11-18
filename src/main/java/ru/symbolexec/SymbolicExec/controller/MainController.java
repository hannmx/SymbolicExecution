package ru.symbolexec.SymbolicExec.controller;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import ru.symbolexec.SymbolicExec.core.ApkAnalyzer;
import ru.symbolexec.SymbolicExec.util.FileHandler;

import java.io.File;

@Controller
public class MainController {

        @GetMapping("/")
        public String index() {
            return "index";
        }

        @PostMapping("/upload")
        public String uploadFile(@RequestParam("file") MultipartFile file, Model model) {
            try {
                FileHandler fileHandler = new FileHandler();
                File apkFile = fileHandler.saveFile(file);

                ApkAnalyzer analyzer = new ApkAnalyzer();
                String reportPath = analyzer.analyzeApk(apkFile);

                model.addAttribute("message", "Analysis completed. Report saved at: " + reportPath);
            } catch (Exception e) {
                model.addAttribute("message", "Error: " + e.getMessage());
            }
            return "index";
        }
}
