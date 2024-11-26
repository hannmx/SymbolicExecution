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

    // Новая структура для хранения уязвимостей по типу, классу и методу
    private final Map<String, Map<String, Set<String>>> vulnerabilitiesByTypeAndClass = new HashMap<>();

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
                analyzeMethodInstructions(className, method);
            }
        }

        // Формируем отчет
        return formatGroupedVulnerabilities();
    }

    // Метод для анализа инструкций конкретного метода
    private void analyzeMethodInstructions(String className, Method method) {
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
                analyzeConditionalBranch(instruction, symbolicStack, className, method.getName());
                continue;
            }

            // Анализ вызова методов
            if (opcodeName.contains("INVOKE")) {
                analyzeMethodInvocation(instruction, symbolicStack, className, method.getName());
                continue;
            }

            // Хардкодированные строки
            if (opcodeName.contains("CONST_STRING")) {
                String str = extractString(instruction);
                symbolicStack.push(str);
                if (isSensitiveString(str)) {
                    addVulnerability("Hardcoded sensitive string", className, method.getName());
                }
            }

            // Обработка исключений
            if (opcodeName.contains("THROW")) {
                analyzeThrowInstruction(instruction, className, method.getName());
            }
        }
    }

    // Новый метод добавления уязвимостей с учетом класса
    private void addVulnerability(String type, String className, String method) {
        vulnerabilitiesByTypeAndClass
                .computeIfAbsent(type, k -> new HashMap<>())
                .computeIfAbsent(className, k -> new HashSet<>())
                .add(method);
    }

    // Старый метод добавления для совместимости
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
    private void analyzeConditionalBranch(Instruction instruction, Stack<String> symbolicStack, String className, String methodName) {
        System.out.println("Analyzing conditional branch in method: " + methodName);
        addVulnerability("Conditional branch detected", className, methodName);
    }

    // Анализ вызова методов
    private void analyzeMethodInvocation(Instruction instruction, Stack<String> symbolicStack, String className, String methodName) {
        String invokedMethod = instruction.toString();
        if (invokedMethod.contains("execSQL")) {
            String sqlQuery = symbolicStack.isEmpty() ? "unknown" : symbolicStack.pop();
            if (sqlQuery.toLowerCase().contains("select")) {
                addVulnerability("Potential SQL injection", className, methodName);
            }
        }
    }

    // Анализ обработки исключений
    private void analyzeThrowInstruction(Instruction instruction, String className, String methodName) {
        System.out.println("Throw detected in method: " + methodName);
        addVulnerability("Unhandled exception", className, methodName);
    }

    // Новый метод форматирования уязвимостей
    protected String formatGroupedVulnerabilities() {
        if (vulnerabilitiesByTypeAndClass.isEmpty()) {
            return "No vulnerabilities detected.";
        }

        StringBuilder report = new StringBuilder("Grouped vulnerabilities:\n");

        // Критические уязвимости
        Map<String, List<String>> criticalVulnerabilities = new HashMap<>();
        Map<String, List<String>> lessCriticalVulnerabilities = new HashMap<>();

        vulnerabilitiesByTypeAndClass.forEach((type, classes) -> {
            classes.forEach((className, methods) -> {
                for (String method : methods) {
                    // Разделяем на критические и менее критичные уязвимости
                    if (type.equals("Potential SQL injection") || type.equals("Hardcoded sensitive string")) {
                        criticalVulnerabilities
                                .computeIfAbsent(type, k -> new ArrayList<>())
                                .add(className + ":" + method);
                    } else {
                        lessCriticalVulnerabilities
                                .computeIfAbsent(type, k -> new ArrayList<>())
                                .add(className + ":" + method);
                    }
                }
            });
        });

        // Выводим критичные уязвимости в первую очередь
        report.append("Critical vulnerabilities:\n");
        criticalVulnerabilities.forEach((type, items) -> {
            report.append("- ").append(type).append(" (").append(items.size()).append(" methods):\n");
            items.stream().limit(2).forEach(item -> report.append("  * ").append(item).append("\n")); // Выводим 2 примера
        });

        // Далее выводим менее критичные
        report.append("\nLess critical vulnerabilities:\n");
        lessCriticalVulnerabilities.forEach((type, items) -> {
            report.append("- ").append(type).append(" (").append(items.size()).append(" methods):\n");
            items.stream().limit(2).forEach(item -> report.append("  * ").append(item).append("\n")); // Выводим 2 примера
        });

        return report.toString();
    }
}
