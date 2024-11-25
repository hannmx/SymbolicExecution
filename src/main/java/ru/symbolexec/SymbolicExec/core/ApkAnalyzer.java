package ru.symbolexec.SymbolicExec.core;

import ru.symbolexec.SymbolicExec.util.ReportGenerator;

import java.io.File;
import java.util.List;

public class ApkAnalyzer {

    // Метод для анализа APK и возвращения детализированных результатов
    public AnalysisResultDto analyzeApk(File apkFile) {
        try {
            System.out.println("Starting analysis for APK: " + apkFile.getName());

            DexParser dexParser = new DexParser();
            List<File> dexFiles = dexParser.extractDex(apkFile);

            if (dexFiles.isEmpty()) {
                throw new RuntimeException("No DEX files extracted. APK might be invalid.");
            }

            System.out.println("DEX files extracted: " + dexFiles.size());
            StringBuilder symbolicReports = new StringBuilder();
            SymbolicExecution symbolicExecution = new SymbolicExecution();

            for (File dexFile : dexFiles) {
                System.out.println("Analyzing DEX file: " + dexFile.getName());
                String symbolicReport = symbolicExecution.analyzeDex(dexFile);
                symbolicReports.append(symbolicReport).append("\n");
            }

            ReportGenerator reportGenerator = new ReportGenerator();
            String reportPath = reportGenerator.generate(symbolicReports.toString());

            System.out.println("Analysis completed successfully. Report saved at: " + reportPath);
            return new AnalysisResultDto(reportPath, symbolicReports.toString());

        } catch (Exception e) {
            System.err.println("Error during APK analysis: " + e.getMessage());
            e.printStackTrace();
            throw new RuntimeException("Error during analysis: " + e.getMessage());
        }
    }
}
