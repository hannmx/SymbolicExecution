package ru.symbolexec.SymbolicExec.core;

import java.io.File;
import java.nio.file.Path;
import java.nio.file.Paths;

public class DexParser {
    private static final String APKTOOL_PATH = "/path/to/apktool";

    public File extractDex(File apkFile) throws Exception {
        // Использование APKTool для декомпиляции APK-файлов и извлечения DEX-файлов
        Path outputDir = Paths.get("output", apkFile.getName());
        ProcessBuilder processBuilder = new ProcessBuilder(
                APKTOOL_PATH, "d", apkFile.getAbsolutePath(), "-o", outputDir.toString());
        Process process = processBuilder.start();
        process.waitFor();

        return outputDir.resolve("classes.dex").toFile();
    }
}
