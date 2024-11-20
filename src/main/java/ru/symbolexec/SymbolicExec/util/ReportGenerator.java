package ru.symbolexec.SymbolicExec.util;

import java.io.File;
import java.io.FileWriter;

public class ReportGenerator {
    public String generate(String reportContent) throws Exception {
        File reportDir = new File("reports");
        if (!reportDir.exists()) {
            reportDir.mkdirs();
        }

        File reportFile = new File(reportDir, "report_" + System.currentTimeMillis() + ".txt");
        try (FileWriter writer = new FileWriter(reportFile)) {
            writer.write(reportContent);
        }
        return reportFile.getAbsolutePath();
    }
}
