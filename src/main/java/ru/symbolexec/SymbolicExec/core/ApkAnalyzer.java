package ru.symbolexec.SymbolicExec.core;

import ru.symbolexec.SymbolicExec.util.ReportGenerator;

import java.io.File;
import java.io.IOException;
import java.util.List;

public class ApkAnalyzer {

    public AnalysisResultDto analyzeApk(File apkFile) {
        try {
            // Проверяем, существует ли файл и является ли он APK
            if (!apkFile.exists() || !apkFile.getName().endsWith(".apk")) {
                throw new IllegalArgumentException("Provided file is not a valid APK: " + apkFile.getName());
            }

            System.out.println("Starting analysis for APK: " + apkFile.getName());

            DexParser dexParser = new DexParser();
            List<File> dexFiles = dexParser.extractDex(apkFile);

            if (dexFiles.isEmpty()) {
                throw new RuntimeException("No DEX files extracted. APK might be invalid.");
            }

            System.out.println("DEX files extracted: " + dexFiles.size());

            // Создаем объект для выполнения символического анализа
            SymbolicExecution symbolicExecution = new SymbolicExecution(apkFile); // Передаем apkFile в SymbolicExecution

            StringBuilder symbolicReports = new StringBuilder();
            for (File dexFile : dexFiles) {
                System.out.println("Analyzing DEX file: " + dexFile.getName());

                // Генерация временного пути для отчета
                String tempReportPath = dexFile.getParent() + File.separator + dexFile.getName() + "_report.txt";

                // Вызываем метод analyzeDex с двумя аргументами
                String symbolicReport = symbolicExecution.analyzeDex(dexFile, tempReportPath);
                symbolicReports.append(symbolicReport).append("\n");
            }

            // Генерация отчета по результатам анализа
            ReportGenerator reportGenerator = new ReportGenerator();
            String reportPath = reportGenerator.generate(symbolicReports.toString());

            // Используем краткий отчет об уязвимостях
            String fullReport = symbolicExecution.formatFullVulnerabilitiesReport();
            String summaryReport = symbolicExecution.formatShortVulnerabilitiesReport();

            System.out.println("Analysis completed successfully. Report saved at: " + reportPath);
            return new AnalysisResultDto(reportPath, fullReport, summaryReport);

        } catch (IOException e) {
            System.err.println("I/O error during APK analysis: " + e.getMessage());
            e.printStackTrace();
            throw new RuntimeException("I/O error during analysis: " + e.getMessage(), e);
        } catch (Exception e) {
            System.err.println("Error during APK analysis: " + e.getMessage());
            e.printStackTrace();
            throw new RuntimeException("Error during analysis: " + e.getMessage(), e);
        }
    }
}
