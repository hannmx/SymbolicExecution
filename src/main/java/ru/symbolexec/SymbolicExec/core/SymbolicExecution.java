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
import java.util.regex.Pattern;

public class SymbolicExecution {

    private final Map<String, Map<String, Set<String>>> vulnerabilitiesByTypeAndClass = new HashMap<>();
    private Deobfuscator deobfuscator;

    private static final Pattern SENSITIVE_PATTERN = Pattern.compile("password|secret|token|key", Pattern.CASE_INSENSITIVE);
    private static final Pattern HTML_PATTERN = Pattern.compile("<.*?>", Pattern.CASE_INSENSITIVE); // Для XSS

    public SymbolicExecution(File apkFile) throws Exception {
        this.deobfuscator = new Deobfuscator(apkFile);  // Инициализация деобфускатора
    }

    // Метод для анализа DEX файла с символьным исполнением
    public String analyzeDex(File dexFile) throws Exception {
        // Чтение содержимого DEX-файла в массив байтов
        byte[] dexBytes = Files.readAllBytes(dexFile.toPath());
        DexBackedDexFile dexBackedDexFile = new DexBackedDexFile(null, dexBytes);

        // Итерация по классам и методам DEX-файла
        Set<String> analyzedMethods = new HashSet<>();
        for (ClassDef classDef : dexBackedDexFile.getClasses()) {
            String className = classDef.getType();
            System.out.println("Анализируем класс: " + className);

            for (Method method : classDef.getMethods()) {
                String methodName = className + ":" + method.getName();
                if (analyzedMethods.contains(methodName)) {
                    continue; // Избегаем повторного анализа
                }
                analyzedMethods.add(methodName);

                System.out.println("  Анализируем метод: " + methodName);
                analyzeMethodInstructions(className, method);
            }
        }

        // Формируем отчет
        return formatGroupedVulnerabilities();
    }

    // Метод для анализа инструкций метода с символьным исполнением
    private void analyzeMethodInstructions(String className, Method method) {
        if (!(method.getImplementation() instanceof DexBackedMethodImplementation)) {
            return;
        }

        DexBackedMethodImplementation implementation = (DexBackedMethodImplementation) method.getImplementation();
        Stack<SymbolicVariable> symbolicStack = new Stack<>();
        Map<String, SymbolicVariable> registers = new HashMap<>();

        // Используем очередь с ограничением размера для путей
        Queue<Map<String, SymbolicVariable>> paths = new LinkedList<>();
        paths.add(new HashMap<>()); // Инициализация первого пути

        for (Instruction instruction : implementation.getInstructions()) {
            String opcodeName = instruction.getOpcode().name();

            // Обработка инструкций в зависимости от их типа
            switch (opcodeName) {
                case "IF":
                    analyzeConditionalBranch(instruction, symbolicStack, className, method.getName(), paths);
                    break;
                case "INVOKE":
                    analyzeMethodInvocation(instruction, symbolicStack, className, method.getName(), paths);
                    break;
                case "CONST_STRING":
                    analyzeConstString(instruction, symbolicStack, className, method.getName());
                    break;
                case "THROW":
                    analyzeThrowInstruction(instruction, className, method.getName());
                    break;
                case "ADD":
                case "SUB":
                case "MUL":
                case "DIV":
                    analyzeArithmeticOperation(instruction, symbolicStack, className, method.getName(), paths);
                    break;
                case "MOVE":
                case "STORE":
                    analyzeMemoryOperation(instruction, symbolicStack, registers, paths);
                    break;
                case "CONCAT":
                    analyzeStringOperation(instruction, symbolicStack, className, method.getName(), paths);
                    break;
                default:
                    // Если инструкция не попала в проверку, пропускаем её
                    break;
            }
        }
    }

    // Обработка жестко закодированных строк
    private void analyzeConstString(Instruction instruction, Stack<SymbolicVariable> symbolicStack,
                                    String className, String methodName) {
        String str = extractString(instruction);
        symbolicStack.push(new SymbolicVariable("str", str));
        if (SENSITIVE_PATTERN.matcher(str).find()) {
            addVulnerability("Жестко закодированная чувствительная строка", className, methodName);
        }
    }

    // Символьное исполнение для анализа строк
    private void analyzeStringOperation(Instruction instruction, Stack<SymbolicVariable> symbolicStack,
                                        String className, String methodName, Queue<Map<String, SymbolicVariable>> paths) {
        SymbolicVariable operand1 = symbolicStack.isEmpty() ? null : symbolicStack.pop();
        SymbolicVariable operand2 = symbolicStack.isEmpty() ? null : symbolicStack.pop();
        String resultExpression = operand1.getExpression() + " + " + operand2.getExpression();
        symbolicStack.push(new SymbolicVariable("result", resultExpression));

        // Проверка на XSS
        if (HTML_PATTERN.matcher(resultExpression).find() || resultExpression.contains("<script>") || resultExpression.contains("alert(")) {
            addVulnerability("Потенциальная XSS уязвимость", className, methodName);
        }
    }

    // Метод добавления уязвимости с учетом деобфусцированных имен
    private void addVulnerability(String type, String className, String method) {
        String deobfuscatedClass = deobfuscator.deobfuscateClassAndMethod(className);
        String deobfuscatedMethod = deobfuscator.deobfuscateClassAndMethod(method);

        vulnerabilitiesByTypeAndClass
                .computeIfAbsent(type, k -> new HashMap<>())
                .computeIfAbsent(deobfuscatedClass, k -> new HashSet<>())
                .add(deobfuscatedMethod);
    }

    // Извлечение строки из инструкции
    private String extractString(Instruction instruction) {
        if (instruction instanceof Instruction22c) {
            return instruction.toString(); // Пример, уточните для вашего случая
        }
        return "";
    }

    // Символьное исполнение для анализа веток выполнения (IF)
    private void analyzeConditionalBranch(Instruction instruction, Stack<SymbolicVariable> symbolicStack,
                                          String className, String methodName, Queue<Map<String, SymbolicVariable>> paths) {
        System.out.println("Анализируем условную ветвь в методе: " + methodName);
        addVulnerability("Обнаружена условная ветвь", className, methodName);

        SymbolicVariable condition = symbolicStack.isEmpty() ? null : symbolicStack.pop();
        Queue<Map<String, SymbolicVariable>> newPaths = new LinkedList<>();
        for (Map<String, SymbolicVariable> path : paths) {
            Map<String, SymbolicVariable> truePath = new HashMap<>(path);
            newPaths.add(truePath);

            Map<String, SymbolicVariable> falsePath = new HashMap<>(path);
            newPaths.add(falsePath);
        }

        // Обрезка путей, если их слишком много
        int maxPaths = 100;
        while (newPaths.size() > maxPaths) {
            newPaths.poll();
        }

        paths.clear();
        paths.addAll(newPaths);
    }

    // Символьное исполнение для вызова методов
    private void analyzeMethodInvocation(Instruction instruction, Stack<SymbolicVariable> symbolicStack,
                                         String className, String methodName, Queue<Map<String, SymbolicVariable>> paths) {
        String invokedMethod = instruction.toString();
        if (invokedMethod.contains("execSQL")) {
            String sqlQuery = symbolicStack.isEmpty() ? "unknown" : symbolicStack.pop().getExpression();
            if (sqlQuery.toLowerCase().contains("select")) {
                addVulnerability("Потенциальная SQL инъекция", className, methodName);
            }
        }
    }

    // Символьное исполнение для обработки исключений
    private void analyzeThrowInstruction(Instruction instruction, String className, String methodName) {
        System.out.println("Обнаружено исключение в методе: " + methodName);
        addVulnerability("Необработанное исключение", className, methodName);
    }

    // Символьное исполнение для арифметических операций
    private void analyzeArithmeticOperation(Instruction instruction, Stack<SymbolicVariable> symbolicStack,
                                            String className, String methodName, Queue<Map<String, SymbolicVariable>> paths) {
        System.out.println("Анализируем арифметическую операцию в методе: " + methodName);
        SymbolicVariable operand1 = symbolicStack.isEmpty() ? null : symbolicStack.pop();
        SymbolicVariable operand2 = symbolicStack.isEmpty() ? null : symbolicStack.pop();

        if (operand1 != null && operand2 != null) {
            String resultExpression = "(" + operand1.getExpression() + " " + instruction.getOpcode().name() + " " + operand2.getExpression() + ")";
            symbolicStack.push(new SymbolicVariable("result", resultExpression));
        }
    }

    // Символьное исполнение для манипуляций с памятью
    private void analyzeMemoryOperation(Instruction instruction, Stack<SymbolicVariable> symbolicStack,
                                        Map<String, SymbolicVariable> registers, Queue<Map<String, SymbolicVariable>> paths) {
        String registerName = instruction.toString();
        SymbolicVariable registerValue = symbolicStack.isEmpty() ? null : symbolicStack.pop();
        if (registerValue != null) {
            registers.put(registerName, registerValue);
        }
    }

    // Метод для форматирования уязвимостей в отчет с улучшенной детализацией и пояснениями
    protected String formatGroupedVulnerabilities() {
        StringBuilder report = new StringBuilder();

        for (Map.Entry<String, Map<String, Set<String>>> entry : vulnerabilitiesByTypeAndClass.entrySet()) {
            String vulnerabilityType = entry.getKey();
            report.append("Уязвимость типа: ").append(vulnerabilityType).append("\n");

            // Добавляем пояснения по типам уязвимостей
            String explanation = getVulnerabilityExplanation(vulnerabilityType);
            if (explanation != null) {
                report.append("  Описание: ").append(explanation).append("\n");
            }

            for (Map.Entry<String, Set<String>> classEntry : entry.getValue().entrySet()) {
                String className = classEntry.getKey();
                report.append("  Класс: ").append(className).append("\n");

                for (String method : classEntry.getValue()) {
                    report.append("    Метод: ").append(method).append("\n");
                    // Добавляем потенциальные последствия
                    String consequences = getConsequencesForMethod(vulnerabilityType, className, method);
                    if (consequences != null) {
                        report.append("      Возможные последствия: ").append(consequences).append("\n");
                    }
                }
            }
        }

        return report.toString();
    }

    // Метод для получения пояснения по типу уязвимости
    private String getVulnerabilityExplanation(String vulnerabilityType) {
        switch (vulnerabilityType) {
            case "Жестко закодированная чувствительная строка":
                return "Строки, содержащие чувствительную информацию (например, пароли или ключи), " +
                        "не должны быть жестко закодированы в коде приложения.";
            case "Потенциальная XSS уязвимость":
                return "Возможность инъекции кода в веб-страницу, что может привести к выполнению произвольных " +
                        "скриптов в браузере пользователя.";
            case "Потенциальная SQL инъекция":
                return "Возможность выполнения произвольных SQL-запросов через приложение, что может привести к " +
                        "выходу за пределы предусмотренных данных или утечке информации.";
            case "Необработанное исключение":
                return "Метод может выбросить исключение, которое не обрабатывается, что может привести к сбою " +
                        "программы или непредсказуемому поведению.";
            default:
                return null;
        }
    }

    // Метод для получения возможных последствий для метода
    private String getConsequencesForMethod(String vulnerabilityType, String className, String methodName) {
        // Здесь можно добавить больше логики для определения последствий на основе уязвимости
        switch (vulnerabilityType) {
            case "Необработанное исключение":
                return "Метод может завершиться с ошибкой, что приведет к сбою приложения в случае этого исключения.";
            case "Потенциальная SQL инъекция":
                return "Это может привести к потере данных или компрометации базы данных приложения.";
            case "Потенциальная XSS уязвимость":
                return "Это может привести к выполнению вредоносных скриптов, что скомпрометирует безопасность " +
                        "пользователей, использующих приложение.";
            case "Жестко закодированная чувствительная строка":
                return "Могут быть утечены важные данные, такие как пароли или ключи, что позволит злоумышленникам " +
                        "получить несанкционированный доступ.";
            default:
                return "Неизвестные последствия.";
        }
    }


    // Класс для символьных переменных
    public static class SymbolicVariable {
        private final String name;
        private final String expression;

        public SymbolicVariable(String name, String expression) {
            this.name = name;
            this.expression = expression;
        }

        public String getExpression() {
            return expression;
        }
    }
}
