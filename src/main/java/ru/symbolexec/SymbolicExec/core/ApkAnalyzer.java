package ru.symbolexec.SymbolicExec.core;

import ru.symbolexec.SymbolicExec.core.DexParser;
import ru.symbolexec.SymbolicExec.util.ReportGenerator;
import java.io.File;

public class ApkAnalyzer {
    public String analyzeApk(File apkFile) {
        try {
            // Извлечение файлов DEX с использованием DexParser
            DexParser dexParser = new DexParser();
            File dexFile = dexParser.extractDex(apkFile);

            // Символьное исполнение
            SymbolicExecution symbolicExecution = new SymbolicExecution();
            String symbolicReport = symbolicExecution.analyzeDex(dexFile);

            // Создание отчета
            ReportGenerator reportGenerator = new ReportGenerator();
            return reportGenerator.generate(symbolicReport);
        } catch (Exception e) {
            return "Error during analysis: " + e.getMessage();
        }
    }
}
