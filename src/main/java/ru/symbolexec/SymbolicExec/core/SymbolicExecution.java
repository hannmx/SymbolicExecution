package ru.symbolexec.SymbolicExec.core;

import org.jf.dexlib2.dexbacked.DexBackedDexFile;
import org.jf.dexlib2.dexbacked.DexBackedMethodImplementation;
import org.jf.dexlib2.iface.ClassDef;
import org.jf.dexlib2.iface.Method;
import org.jf.dexlib2.iface.instruction.Instruction;

import java.io.File;
import java.nio.file.Files;
import java.util.*;

public class SymbolicExecution {

    // Карта для хранения типов уязвимостей и соответствующих методов
    private final Map<String, Set<String>> vulnerabilities = new HashMap<>();

    public String analyzeDex(File dexFile) throws Exception {
        // Чтение содержимого DEX-файла в массив байтов
        byte[] dexBytes = Files.readAllBytes(dexFile.toPath());
        DexBackedDexFile dexBackedDexFile = new DexBackedDexFile(null, dexBytes);

        // Итерация по классам и методам DEX-файла
        Set<String> analyzedMethods = new HashSet<>();
        for (ClassDef classDef : dexBackedDexFile.getClasses()) {
            String className = classDef.getType();
            System.out.println("Analyzing class: " + className);

            for (Method method : classDef.getMethods()) {
                String methodName = className + ":" + method.getName();
                if (analyzedMethods.contains(methodName)) {
                    continue; // Избегаем повторного анализа
                }
                analyzedMethods.add(methodName);

                System.out.println("  Analyzing method: " + methodName);
                analyzeMethodInstructions(method);
            }
        }

        // Формируем отчет
        return formatVulnerabilities();
    }

    // Метод для анализа инструкций конкретного метода
    private void analyzeMethodInstructions(Method method) {
        if (!(method.getImplementation() instanceof DexBackedMethodImplementation)) {
            return;
        }

        DexBackedMethodImplementation implementation = (DexBackedMethodImplementation) method.getImplementation();
        for (Instruction instruction : implementation.getInstructions()) {
            String opcodeName = instruction.getOpcode().name();

            // Проверка на некорректные условия (только критические действия)
            if (opcodeName.contains("IF") && containsCriticalCheck(instruction)) {
                addVulnerability("Conditional check", method.getName());
            }

            // Хардкодированные строки (проверяем чувствительность данных)
            if (opcodeName.contains("CONST_STRING") && isSensitiveString(instruction)) {
                addVulnerability("Hardcoded string", method.getName());
            }

            // Потенциальные SQL-инъекции
            if (opcodeName.contains("INVOKE") && instruction.toString().contains("execSQL")) {
                addVulnerability("Potential SQL injection", method.getName());
            }

            // Отсутствие обработки исключений
            if (opcodeName.contains("THROW")) {
                addVulnerability("Unhandled exception", method.getName());
            }
        }
    }

    // Добавление уязвимости в карту
    private void addVulnerability(String type, String method) {
        vulnerabilities.computeIfAbsent(type, k -> new HashSet<>()).add(method);
    }

    // Проверка на чувствительность строки
    private boolean isSensitiveString(Instruction instruction) {
        String instructionDetails = instruction.toString().toLowerCase();
        return instructionDetails.contains("password") || instructionDetails.contains("secret");
    }

    // Проверка на критические условные проверки
    private boolean containsCriticalCheck(Instruction instruction) {
        // Проверяем, связана ли инструкция с критическим действием (пример)
        String instructionDetails = instruction.toString().toLowerCase();
        return instructionDetails.contains("auth") || instructionDetails.contains("permission");
    }

    // Форматирование найденных уязвимостей
    private String formatVulnerabilities() {
        if (vulnerabilities.isEmpty()) {
            return "No vulnerabilities detected.";
        }

        StringBuilder report = new StringBuilder("Detected vulnerabilities:\n");

        // Группируем уязвимости по типам
        for (Map.Entry<String, Set<String>> entry : vulnerabilities.entrySet()) {
            report.append("- ").append(entry.getKey()).append(" found in methods:\n");
            List<String> sortedMethods = new ArrayList<>(entry.getValue());
            Collections.sort(sortedMethods); // Сортируем методы для улучшения восприятия

            // Выводим только уникальные методы
            for (String method : sortedMethods) {
                report.append("  - ").append(method).append("\n");
            }
        }

        // Убираем повторения и выводим компактно
        return report.toString();
    }
}
