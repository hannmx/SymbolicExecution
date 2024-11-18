package ru.symbolexec.SymbolicExec.util;

import org.springframework.web.multipart.MultipartFile;

import java.io.File;
import java.io.IOException;

public class FileHandler {
    public File saveFile(MultipartFile file) throws IOException {
        File savedFile = new File("uploads/" + file.getOriginalFilename());
        file.transferTo(savedFile);
        return savedFile;
    }
}
