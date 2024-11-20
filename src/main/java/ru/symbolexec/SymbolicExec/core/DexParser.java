package ru.symbolexec.SymbolicExec.core;

import java.io.File;
import java.nio.file.Path;
import java.nio.file.Paths;

public class DexParser {
    private static final String APKTOOL_PATH = "C:\\APKTool\\apktool.jar";

    public File extractDex(File apkFile) throws Exception {
        if (!new File(APKTOOL_PATH).exists()) {
            throw new RuntimeException("APKTool not found at: " + APKTOOL_PATH);
        }

        Path outputDir = Paths.get("output", apkFile.getName());
        ProcessBuilder processBuilder = new ProcessBuilder(
                "java", "-jar", APKTOOL_PATH, "d", apkFile.getAbsolutePath(), "-o", outputDir.toString());
        processBuilder.inheritIO(); // Для отображения вывода процесса
        Process process = processBuilder.start();
        int exitCode = process.waitFor();

        if (exitCode != 0) {
            throw new RuntimeException("APKTool failed to process APK: " + apkFile.getName());
        }

        File dexFile = outputDir.resolve("classes.dex").toFile();
        if (!dexFile.exists()) {
            throw new RuntimeException("DEX file not found in output directory!");
        }

        return dexFile;
    }
}
