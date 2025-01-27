package ru.symbolexec.SymbolicExec.core;

import org.jf.dexlib2.dexbacked.DexBackedDexFile;
import org.jf.dexlib2.dexbacked.DexBackedMethodImplementation;
import org.jf.dexlib2.dexbacked.instruction.DexBackedInstruction21c;
import org.jf.dexlib2.dexbacked.instruction.DexBackedInstruction35c;
import org.jf.dexlib2.iface.ClassDef;
import org.jf.dexlib2.iface.Method;
import org.jf.dexlib2.iface.instruction.Instruction;
import org.jf.dexlib2.iface.reference.StringReference;

import java.io.File;
import java.io.FileWriter;
import java.nio.file.Files;
import java.util.*;
import java.util.regex.Pattern;
import java.util.logging.Logger;

public class SymbolicExecution {

    private static final Logger LOGGER = Logger.getLogger(SymbolicExecution.class.getName());
    private final Map<String, Map<String, Set<String>>> vulnerabilitiesByTypeAndClass = new HashMap<>();
    private final Deobfuscator deobfuscator;

    private final Map<String, InstructionAnalyzer> instructionAnalyzers = new HashMap<>();

    private static final Pattern SENSITIVE_PATTERN = Pattern.compile("password|secret|token|key", Pattern.CASE_INSENSITIVE);
    private static final Pattern HTML_PATTERN = Pattern.compile("<.*?>", Pattern.CASE_INSENSITIVE); // Для XSS

    public SymbolicExecution(File apkFile) throws Exception {
        this.deobfuscator = new Deobfuscator(apkFile); // Инициализация деобфускатора
        registerInstructionAnalyzers();
    }

    private void registerInstructionAnalyzers() {
        instructionAnalyzers.put("IF", this::analyzeConditionalBranch);
        instructionAnalyzers.put("INVOKE", this::analyzeMethodInvocation);
        instructionAnalyzers.put("CONST_STRING", this::analyzeConstString);
        instructionAnalyzers.put("THROW", this::analyzeThrowInstruction);
        instructionAnalyzers.put("ADD", this::analyzeArithmeticOperation);
        instructionAnalyzers.put("SUB", this::analyzeArithmeticOperation);
        instructionAnalyzers.put("MUL", this::analyzeArithmeticOperation);
        instructionAnalyzers.put("DIV", this::analyzeArithmeticOperation);
        instructionAnalyzers.put("MOVE", this::analyzeMemoryOperation);
        instructionAnalyzers.put("STORE", this::analyzeMemoryOperation);
        instructionAnalyzers.put("CONCAT", this::analyzeStringOperation);
        instructionAnalyzers.put("NEG", this::analyzeUnaryOperation); // Обработка унарных операций
        instructionAnalyzers.put("SHL", this::analyzeShiftOperation); // Обработка сдвигов
        instructionAnalyzers.put("SHR", this::analyzeShiftOperation);
        instructionAnalyzers.put("USHR", this::analyzeShiftOperation);
    }

    private void analyzeConditionalBranch(Instruction instruction, Stack<SymbolicVariable> symbolicStack, String className, String methodName, Queue<Map<String, SymbolicVariable>> paths, Map<String, SymbolicVariable> registers) {
        SymbolicVariable condition = symbolicStack.isEmpty() ? null : symbolicStack.pop();
        if (condition != null) {
            String branchCondition = "Condition: " + condition.getExpression();
            LOGGER.info("Analyzing conditional branch in " + className + ":" + methodName + " -> " + branchCondition);
        }
    }

    private void analyzeMethodInvocation(Instruction instruction, Stack<SymbolicVariable> symbolicStack, String className, String methodName, Queue<Map<String, SymbolicVariable>> paths, Map<String, SymbolicVariable> registers) {
        String invokedMethod = instruction.toString(); // Можно улучшить извлечение метода
        LOGGER.info("Method invocation detected: " + invokedMethod + " in " + className + ":" + methodName);
    }

    private String extractString(Instruction instruction) {
        if (instruction instanceof org.jf.dexlib2.dexbacked.instruction.DexBackedInstruction35c) {
            DexBackedInstruction35c instr = (DexBackedInstruction35c) instruction;
            if (instr.getReference() instanceof org.jf.dexlib2.iface.reference.StringReference) {
                return ((StringReference) instr.getReference()).getString();
            }
        } else if (instruction instanceof org.jf.dexlib2.dexbacked.instruction.DexBackedInstruction21c) {
            DexBackedInstruction21c instr = (DexBackedInstruction21c) instruction;
            if (instr.getReference() instanceof org.jf.dexlib2.iface.reference.StringReference) {
                return ((StringReference) instr.getReference()).getString();
            }
        }
        return instruction.toString();
    }

    private void analyzeConstString(Instruction instruction, Stack<SymbolicVariable> symbolicStack, String className, String methodName, Queue<Map<String, SymbolicVariable>> paths, Map<String, SymbolicVariable> registers) {
        String str = extractString(instruction);
        symbolicStack.push(new SymbolicVariable("str", str));
        if (SENSITIVE_PATTERN.matcher(str).find()) {
            addVulnerability("Hardcoded sensitive string", className, methodName);
            LOGGER.warning("Sensitive string found in " + className + ":" + methodName + " -> " + str);
        }
    }

    private void analyzeThrowInstruction(Instruction instruction, Stack<SymbolicVariable> symbolicStack, String className, String methodName, Queue<Map<String, SymbolicVariable>> paths, Map<String, SymbolicVariable> registers) {
        addVulnerability("Unhandled exception", className, methodName);
        LOGGER.warning("Unhandled exception in " + className + ":" + methodName);
    }

    private void analyzeArithmeticOperation(Instruction instruction, Stack<SymbolicVariable> symbolicStack, String className, String methodName, Queue<Map<String, SymbolicVariable>> paths, Map<String, SymbolicVariable> registers) {
        SymbolicVariable operand1 = symbolicStack.isEmpty() ? null : symbolicStack.pop();
        SymbolicVariable operand2 = symbolicStack.isEmpty() ? null : symbolicStack.pop();
        if (operand1 != null && operand2 != null) {
            String resultExpression = "(" + operand1.getExpression() + " " + instruction.getOpcode().name() + " " + operand2.getExpression() + ")";
            symbolicStack.push(new SymbolicVariable("result", resultExpression));
            LOGGER.info("Arithmetic operation in " + className + ":" + methodName + " -> " + resultExpression);
        }
    }

    private void analyzeMemoryOperation(Instruction instruction, Stack<SymbolicVariable> symbolicStack, String className, String methodName, Queue<Map<String, SymbolicVariable>> paths, Map<String, SymbolicVariable> registers) {
        String registerName = instruction.toString();
        SymbolicVariable registerValue = symbolicStack.isEmpty() ? null : symbolicStack.pop();
        if (registerValue != null) {
            registers.put(registerName, registerValue);
            LOGGER.info("Memory operation: Register " + registerName + " = " + registerValue.getExpression());
        }
    }

    private void analyzeStringOperation(Instruction instruction, Stack<SymbolicVariable> symbolicStack, String className, String methodName, Queue<Map<String, SymbolicVariable>> paths, Map<String, SymbolicVariable> registers) {
        SymbolicVariable operand1 = symbolicStack.isEmpty() ? null : symbolicStack.pop();
        SymbolicVariable operand2 = symbolicStack.isEmpty() ? null : symbolicStack.pop();
        if (operand1 != null && operand2 != null) {
            String concatenated = operand1.getExpression() + " + " + operand2.getExpression();
            symbolicStack.push(new SymbolicVariable("result", concatenated));
            LOGGER.info("String operation in " + className + ":" + methodName + " -> " + concatenated);
        }
    }

    private void analyzeUnaryOperation(Instruction instruction, Stack<SymbolicVariable> symbolicStack, String className, String methodName, Queue<Map<String, SymbolicVariable>> paths, Map<String, SymbolicVariable> registers) {
        SymbolicVariable operand = symbolicStack.isEmpty() ? null : symbolicStack.pop();
        if (operand != null) {
            String resultExpression = "-" + operand.getExpression();
            symbolicStack.push(new SymbolicVariable("result", resultExpression));
            LOGGER.info("Unary operation in " + className + ":" + methodName + " -> " + resultExpression);
        }
    }

    private void analyzeShiftOperation(Instruction instruction, Stack<SymbolicVariable> symbolicStack, String className, String methodName, Queue<Map<String, SymbolicVariable>> paths, Map<String, SymbolicVariable> registers) {
        SymbolicVariable operand = symbolicStack.isEmpty() ? null : symbolicStack.pop();
        if (operand != null) {
            String resultExpression = operand.getExpression() + " " + instruction.getOpcode().name();
            symbolicStack.push(new SymbolicVariable("result", resultExpression));
            LOGGER.info("Shift operation in " + className + ":" + methodName + " -> " + resultExpression);
        }
    }

    public String analyzeDex(File dexFile, String reportFilePath) throws Exception {
        byte[] dexBytes = Files.readAllBytes(dexFile.toPath());
        DexBackedDexFile dexBackedDexFile = new DexBackedDexFile(null, dexBytes);

        Set<String> analyzedMethods = new HashSet<>();
        for (ClassDef classDef : dexBackedDexFile.getClasses()) {
            String className = classDef.getType();
            LOGGER.info("Анализируем класс: " + className);

            for (Method method : classDef.getMethods()) {
                String methodName = className + ":" + method.getName();
                if (analyzedMethods.contains(methodName)) {
                    continue;
                }
                analyzedMethods.add(methodName);

                LOGGER.info("  Анализируем метод: " + methodName);
                analyzeMethodInstructions(className, method);
            }
        }

        String fullReport = formatFullVulnerabilitiesReport();
        saveReportToFile(fullReport, reportFilePath);

        return formatShortVulnerabilitiesReport();
    }

    private void analyzeMethodInstructions(String className, Method method) {
        if (!(method.getImplementation() instanceof DexBackedMethodImplementation)) {
            return;
        }

        DexBackedMethodImplementation implementation = (DexBackedMethodImplementation) method.getImplementation();
        Stack<SymbolicVariable> symbolicStack = new Stack<>();
        Map<String, SymbolicVariable> registers = new HashMap<>();
        Queue<Map<String, SymbolicVariable>> paths = new LinkedList<>();
        paths.add(new HashMap<>()); // Инициализация первого пути

        for (Instruction instruction : implementation.getInstructions()) {
            String opcodeName = instruction.getOpcode().name();
            InstructionAnalyzer analyzer = instructionAnalyzers.get(opcodeName);
            if (analyzer != null) {
                analyzer.analyze(instruction, symbolicStack, className, method.getName(), paths, registers);
            } else {
                LOGGER.fine("Неизвестная инструкция: " + opcodeName);
            }
        }
    }

    private void saveReportToFile(String report, String filePath) throws Exception {
        try (FileWriter writer = new FileWriter(filePath)) {
            writer.write(report);
        }
    }

    private String formatFullVulnerabilitiesReport() {
        StringBuilder report = new StringBuilder("Полный отчет об уязвимостях:\n");
        for (Map.Entry<String, Map<String, Set<String>>> entry : vulnerabilitiesByTypeAndClass.entrySet()) {
            report.append("Тип уязвимости: ").append(entry.getKey()).append("\n");
            for (Map.Entry<String, Set<String>> classEntry : entry.getValue().entrySet()) {
                report.append("  Класс: ").append(classEntry.getKey()).append("\n");
                for (String method : classEntry.getValue()) {
                    report.append("    Метод: ").append(method).append("\n");
                }
            }
        }
        return report.toString();
    }

    protected String formatShortVulnerabilitiesReport() {
        StringBuilder report = new StringBuilder("Краткий отчет об уязвимостях:\n");
        vulnerabilitiesByTypeAndClass.forEach((type, classes) -> {
            report.append("Тип уязвимости: ").append(type).append("\n");
            classes.entrySet().stream()
                    .sorted((a, b) -> b.getValue().size() - a.getValue().size())
                    .limit(5)
                    .forEach(entry -> {
                        report.append("  Класс: ").append(entry.getKey()).append(" (").append(entry.getValue().size()).append(" методов)\n");
                    });
        });
        return report.toString();
    }

    private void addVulnerability(String type, String className, String method) {
        if (type.equals("Hardcoded sensitive string")) {
            type = "Жестко закодированная чувствительная строка";
        } else if (type.equals("Unhandled exception")) {
            type = "Необработанное исключение";
        } else if (type.equals("Null Pointer Dereference")) {
            type = "Разыменование null-указателя";
        } else if (type.equals("SQL Injection")) {
            type = "SQL-инъекция";
        } else if (type.equals("Cross-Site Scripting (XSS)")) {
            type = "Межсайтовое скриптование (XSS)";
        } else if (type.equals("Insecure Randomness")) {
            type = "Ненадежная случайность";
        } else if (type.equals("Insecure Communication (No Encryption)")) {
            type = "Не защищенная коммуникация (без шифрования)";
        } else if (type.equals("Buffer Overflow")) {
            type = "Переполнение буфера";
        } else if (type.equals("Improper Input Validation")) {
            type = "Неверная валидация ввода";
        } else if (type.equals("Command Injection")) {
            type = "Инъекция команд";
        } else if (type.equals("Insecure Direct Object References (IDOR)")) {
            type = "Небезопасные прямые ссылки на объекты (IDOR)";
        } else if (type.equals("Cross-Site Request Forgery (CSRF)")) {
            type = "Мошенничество с межсайтовыми запросами (CSRF)";
        } else if (type.equals("Broken Authentication")) {
            type = "Нарушенная аутентификация";
        } else if (type.equals("Sensitive Data Exposure")) {
            type = "Разглашение чувствительных данных";
        } else if (type.equals("Improper Authorization")) {
            type = "Неверная авторизация";
        } else if (type.equals("Path Traversal")) {
            type = "Путевая уязвимость";
        } else if (type.equals("Race Condition")) {
            type = "Условие гонки";
        } else if (type.equals("Privilege Escalation")) {
            type = "Эскалация привилегий";
        } else if (type.equals("Hardcoded Credentials")) {
            type = "Жестко закодированные учетные данные";
        } else if (type.equals("Unsecured File Upload")) {
            type = "Не защищенная загрузка файлов";
        } else if (type.equals("Memory Leak")) {
            type = "Утечка памяти";
        } else if (type.equals("Improper Error Handling")) {
            type = "Неверная обработка ошибок";
        } else if (type.equals("Directory Traversal")) {
            type = "Перебор директорий";
        } else if (type.equals("Weak Password Policy")) {
            type = "Слабая политика паролей";
        } else if (type.equals("Use of Hardcoded Cryptographic Keys")) {
            type = "Использование жестко закодированных криптографических ключей";
        } else if (type.equals("Denial of Service (DoS)")) {
            type = "Отказ в обслуживании (DoS)";
        } else if (type.equals("Improper Session Handling")) {
            type = "Неверная обработка сессий";
        }

        // Дешифровка классов и методов
        String deobfuscatedClass = deobfuscator.deobfuscateClassAndMethod(className);
        String deobfuscatedMethod = deobfuscator.deobfuscateClassAndMethod(method);

        // Если дешифровка не удалась, используем оригинальные значения
        if (deobfuscatedClass == null || deobfuscatedMethod == null) {
            // Логирование ошибки дешифровки
            LOGGER.warning("Ошибка дешифровки для класса: " + className + " и метода: " + method);
            deobfuscatedClass = className;
            deobfuscatedMethod = method; // Используем оригинальные имена
        }

        // Проверка на наличие уже добавленной уязвимости для этого метода
        Map<String, Set<String>> classes = vulnerabilitiesByTypeAndClass.computeIfAbsent(type, k -> new HashMap<>());
        Set<String> methods = classes.computeIfAbsent(deobfuscatedClass, k -> new HashSet<>());

        // Если уязвимость уже есть, не добавляем её повторно
        if (methods.contains(deobfuscatedMethod)) {
            LOGGER.info("Уязвимость уже добавлена для " + deobfuscatedClass + ":" + deobfuscatedMethod);
            return;
        }

        // Добавление уязвимости в коллекцию
        methods.add(deobfuscatedMethod);
        LOGGER.info("Добавлена уязвимость: " + type + " в " + deobfuscatedClass + ":" + deobfuscatedMethod);
    }




    @FunctionalInterface
    private interface InstructionAnalyzer {
        void analyze(Instruction instruction, Stack<SymbolicVariable> symbolicStack, String className, String methodName, Queue<Map<String, SymbolicVariable>> paths, Map<String, SymbolicVariable> registers);
    }

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
