package ru.symbolexec.SymbolicExec.util;

import org.springframework.web.multipart.MultipartFile;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.Enumeration;

public class FileHandler {

    // Метод для сохранения загруженного файла
    public File saveFile(MultipartFile file) throws IOException {
        File savedFile = new File(System.getProperty("java.io.tmpdir") + "/" + file.getOriginalFilename());
        file.transferTo(savedFile);
        return savedFile;
    }

    // Новый метод: извлечение DEX-файла из APK
    public File extractDexFile(File apkFile) throws IOException {
        File dexFile = null;

        try (ZipFile zipFile = new ZipFile(apkFile)) {
            Enumeration<? extends ZipEntry> entries = zipFile.entries();
            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                if (entry.getName().endsWith(".dex")) {
                    File outputDexFile = new File(System.getProperty("java.io.tmpdir") + "/classes.dex");
                    Files.copy(zipFile.getInputStream(entry), outputDexFile.toPath());
                    dexFile = outputDexFile;
                    break;
                }
            }
        }

        return dexFile;
    }
}
