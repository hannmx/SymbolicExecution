package ru.symbolexec.SymbolicExec.core;

import java.io.*;
import java.nio.file.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

public class DexParser {

    // Извлечение DEX-файлов из APK
    public List<File> extractDex(File apkFile) throws Exception {
        // Проверяем, что APK файл существует
        if (!apkFile.exists()) {
            throw new RuntimeException("APK file not found: " + apkFile.getAbsolutePath());
        }

        // Создаем директорию для извлеченных файлов
        Path outputDir = Path.of("output", apkFile.getName().replace(".apk", ""));
        if (Files.exists(outputDir)) {
            deleteDirectory(outputDir.toFile()); // Удаляем старую директорию, если она существует
        }
        Files.createDirectories(outputDir);

        // Извлекаем содержимое APK в созданную директорию
        extractApk(apkFile, outputDir);

        // Находим все DEX файлы в директории
        List<File> dexFiles = new ArrayList<>();
        File[] dexFilesArray = outputDir.toFile().listFiles((dir, name) -> name.endsWith(".dex"));
        if (dexFilesArray != null) {
            dexFiles.addAll(Arrays.asList(dexFilesArray));
        }

        if (dexFiles.isEmpty()) {
            throw new RuntimeException("No DEX files found in APK: " + apkFile.getName());
        }

        return dexFiles;
    }

    // Метод для извлечения содержимого APK
    private void extractApk(File apkFile, Path outputDir) throws IOException {
        try (ZipInputStream zis = new ZipInputStream(new FileInputStream(apkFile))) {
            ZipEntry entry;
            while ((entry = zis.getNextEntry()) != null) {
                // Строим полный путь к файлу
                File outputFile = new File(outputDir.toFile(), entry.getName());

                // Если это директория, создаем ее
                if (entry.isDirectory()) {
                    outputFile.mkdirs();
                } else {
                    // Если это файл, извлекаем его
                    File parentDir = outputFile.getParentFile();
                    if (!parentDir.exists()) {
                        parentDir.mkdirs();  // Создаем родительскую директорию, если она не существует
                    }

                    try (FileOutputStream fos = new FileOutputStream(outputFile)) {
                        byte[] buffer = new byte[1024];
                        int len;
                        while ((len = zis.read(buffer)) > 0) {
                            fos.write(buffer, 0, len);
                        }
                    }
                }
                zis.closeEntry();
            }
        }
    }

    // Метод для удаления директории
    private void deleteDirectory(File directory) {
        if (directory.isDirectory()) {
            for (File file : directory.listFiles()) {
                deleteDirectory(file); // Рекурсивно удаляем файлы в директории
            }
        }
        directory.delete(); // Удаляем сам файл или директорию
    }
}
