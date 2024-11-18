package ru.symbolexec.SymbolicExec.util;

import java.io.File;
import java.io.FileWriter;

public class ReportGenerator {
    public String generate(String reportContent) throws Exception {
        File reportFile = new File("reports/report.txt");
        try (FileWriter writer = new FileWriter(reportFile)) {
            writer.write(reportContent);
        }
        return reportFile.getAbsolutePath();
    }
}
