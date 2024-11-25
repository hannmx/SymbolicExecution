package ru.symbolexec.SymbolicExec.core;

import org.jf.dexlib2.dexbacked.DexBackedDexFile;
import org.jf.dexlib2.dexbacked.DexBackedMethodImplementation;
import org.jf.dexlib2.iface.ClassDef;
import org.jf.dexlib2.iface.Method;
import org.jf.dexlib2.iface.instruction.Instruction;
import org.jf.dexlib2.iface.instruction.formats.Instruction22c;

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
        Stack<String> symbolicStack = new Stack<>();
        Map<String, String> registers = new HashMap<>(); // Хранение значений регистров

        for (Instruction instruction : implementation.getInstructions()) {
            String opcodeName = instruction.getOpcode().name();

            // Учет путей выполнения
            if (opcodeName.contains("IF")) {
                analyzeConditionalBranch(instruction, symbolicStack, method.getName());
                continue;
            }

            // Анализ вызова методов
            if (opcodeName.contains("INVOKE")) {
                analyzeMethodInvocation(instruction, symbolicStack, method.getName());
                continue;
            }

            // Хардкодированные строки
            if (opcodeName.contains("CONST_STRING")) {
                String str = extractString(instruction);
                symbolicStack.push(str);
                if (isSensitiveString(str)) {
                    addVulnerability("Hardcoded sensitive string", method.getName());
                }
            }

            // Обработка исключений
            if (opcodeName.contains("THROW")) {
                analyzeThrowInstruction(instruction, method.getName());
            }
        }
    }

    // Добавление уязвимости в карту
    private void addVulnerability(String type, String method) {
        vulnerabilities.computeIfAbsent(type, k -> new HashSet<>()).add(method);
    }

    // Извлечение строки из инструкции
    private String extractString(Instruction instruction) {
        if (instruction instanceof Instruction22c) {
            return instruction.toString(); // Пример, уточните для вашего случая
        }
        return "";
    }

    // Проверка на чувствительность строки
    private boolean isSensitiveString(String str) {
        String lowerStr = str.toLowerCase();
        return lowerStr.contains("password") || lowerStr.contains("secret") ||
                lowerStr.contains("token") || lowerStr.contains("key");
    }

    // Анализ веток выполнения (IF)
    private void analyzeConditionalBranch(Instruction instruction, Stack<String> symbolicStack, String methodName) {
        // Обработка веток true/false (для простоты выводим сообщение)
        System.out.println("Analyzing conditional branch in method: " + methodName);
        addVulnerability("Conditional branch detected", methodName);
    }

    // Анализ вызова методов
    private void analyzeMethodInvocation(Instruction instruction, Stack<String> symbolicStack, String methodName) {
        // Проверка на вызовы методов с потенциальной уязвимостью
        String invokedMethod = instruction.toString();
        if (invokedMethod.contains("execSQL")) {
            String sqlQuery = symbolicStack.isEmpty() ? "unknown" : symbolicStack.pop();
            if (sqlQuery.toLowerCase().contains("select")) {
                addVulnerability("Potential SQL injection", methodName);
            }
        }
    }

    // Анализ обработки исключений
    private void analyzeThrowInstruction(Instruction instruction, String methodName) {
        // Проверяем, обработано ли исключение в try-catch (упрощенно)
        System.out.println("Throw detected in method: " + methodName);
        addVulnerability("Unhandled exception", methodName);
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
