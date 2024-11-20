package ru.symbolexec.SymbolicExec.core;

import ru.symbolexec.SymbolicExec.core.DexParser;
import ru.symbolexec.SymbolicExec.util.ReportGenerator;

import java.io.File;

public class ApkAnalyzer {
    public String analyzeApk(File apkFile) {
        try {
            // Лог: начало анализа
            System.out.println("Starting analysis for APK: " + apkFile.getName());

            // Шаг 1: Извлечение DEX-файла
            DexParser dexParser = new DexParser();
            File dexFile = dexParser.extractDex(apkFile);

            if (!dexFile.exists() || !dexFile.isFile()) {
                throw new RuntimeException("DEX file extraction failed!");
            }

            // Шаг 2: Символьное исполнение
            SymbolicExecution symbolicExecution = new SymbolicExecution();
            String symbolicReport = symbolicExecution.analyzeDex(dexFile);

            // Шаг 3: Генерация отчёта
            ReportGenerator reportGenerator = new ReportGenerator();
            String reportPath = reportGenerator.generate(symbolicReport);

            // Лог: успешное завершение
            System.out.println("Analysis completed successfully. Report saved at: " + reportPath);

            return reportPath;
        } catch (Exception e) {
            // Лог ошибок
            System.err.println("Error during APK analysis: " + e.getMessage());
            return "Error during analysis: " + e.getMessage();
        }
    }
}
