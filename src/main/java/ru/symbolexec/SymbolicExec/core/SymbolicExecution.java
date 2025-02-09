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

    protected String formatFullVulnerabilitiesReport() {
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

    private String getSolutionForVulnerability(String type) {
        return switch (type) {
            case "Необработанное исключение" -> "Добавьте обработку исключений (try-catch) и логирование ошибок.";
            case "Жестко закодированная чувствительная строка" -> "Используйте безопасное хранилище для конфиденциальных данных.";
            case "SQL-инъекция" -> "Используйте PreparedStatement или ORM для безопасных SQL-запросов.";
            case "Разыменование null-указателя" -> "Проверьте указатели на null перед их использованием или используйте Optional.";
            case "Межсайтовое скриптование (XSS)" -> "Используйте экранирование выводимых данных и валидируйте входные данные.";
            case "Ненадежная случайность" -> "Используйте безопасные криптографические генераторы случайных чисел (например, SecureRandom).";
            case "Не защищенная коммуникация (без шифрования)" -> "Используйте HTTPS для шифрования данных в передаче.";
            case "Переполнение буфера" -> "Проверьте размеры всех буферов и используйте безопасные функции для работы с памятью.";
            case "Неверная валидация ввода" -> "Проверяйте и фильтруйте все входные данные на стороне сервера.";
            case "Инъекция команд" -> "Используйте безопасные механизмы вызова внешних команд (например, ProcessBuilder) с параметризацией.";
            case "Небезопасные прямые ссылки на объекты (IDOR)" -> "Проверьте права доступа к объектам и используйте UUID для уникальных идентификаторов.";
            case "Мошенничество с межсайтовыми запросами (CSRF)" -> "Используйте токены для защиты от CSRF-атак в формах и запросах.";
            case "Нарушенная аутентификация" -> "Используйте многофакторную аутентификацию и защищенные механизмы хранения паролей.";
            case "Разглашение чувствительных данных" -> "Шифруйте данные, а также ограничьте доступ к ним по принципу наименьших привилегий.";
            case "Неверная авторизация" -> "Убедитесь, что проверка прав доступа осуществляется на каждом уровне приложения.";
            case "Путевая уязвимость" -> "Проверьте пути к файлам и директориям и используйте безопасные методы работы с файлами.";
            case "Условие гонки" -> "Используйте синхронизацию и механизмы блокировки при доступе к разделяемым ресурсам.";
            case "Эскалация привилегий" -> "Ограничьте доступ к административным правам и проводите регулярные аудиты безопасности.";
            case "Жестко закодированные учетные данные" -> "Используйте безопасное хранилище для учетных данных, таких как менеджеры секретов.";
            case "Не защищенная загрузка файлов" -> "Проверяйте типы загружаемых файлов и ограничьте размер файлов для загрузки.";
            case "Утечка памяти" -> "Используйте сборщик мусора и отслеживайте утечки с помощью инструментов профилирования памяти.";
            case "Неверная обработка ошибок" -> "Обрабатывайте ошибки корректно, избегайте раскрытия внутренних данных (например, стеков ошибок) в ответах пользователю.";
            case "Перебор директорий" -> "Используйте абсолютные пути для доступа к файлам и проверяйте пути на безопасность.";
            case "Слабая политика паролей" -> "Применяйте строгие требования к паролям: длина, сложность и периодичность смены.";
            case "Использование жестко закодированных криптографических ключей" -> "Используйте безопасные методы хранения криптографических ключей (например, в HSM или через менеджеры секретов).";
            case "Отказ в обслуживании (DoS)" -> "Защищайте серверы от перегрузки с помощью лимита запросов и балансировки нагрузки.";
            case "Неверная обработка сессий" -> "Используйте защищенные cookie для хранения сессий и правильно управляйте временем жизни сессий.";
            default -> "Рекомендуется провести дополнительный аудит кода для выявления и устранения уязвимостей.";
        };
    }


    protected String formatShortVulnerabilitiesReport() {
        StringBuilder report = new StringBuilder("Краткий отчет об уязвимостях:\n");

        vulnerabilitiesByTypeAndClass.forEach((type, classes) -> {
            int totalCriticalIssues = classes.values().stream()
                    .mapToInt(Set::size) // Подсчитываем количество элементов в каждой List
                    .sum();
            // Подсчет всех уязвимостей данного типа
            String solution = getSolutionForVulnerability(type); // Получаем решение для типа уязвимости

            report.append("Тип уязвимости: ").append(type).append("\n");
            report.append("  Количество критических уязвимостей: ").append(totalCriticalIssues).append("\n");

            classes.entrySet().stream()
                    .sorted((a, b) -> b.getValue().size() - a.getValue().size()) // Сортируем по количеству методов
                    .limit(5) // Выводим топ-5 классов
                    .forEach(entry -> {
                        report.append("  Класс: ").append(entry.getKey())
                                .append(" (").append(entry.getValue().size()).append(" методов)\n");
                    });

            report.append("  Возможное решение: ").append(solution).append("\n\n");
        });
        return report.toString();
    }


    private static final Map<String, String> VULNERABILITY_TYPES = Map.ofEntries(
            Map.entry("Hardcoded sensitive string", "Жестко закодированная чувствительная строка"),
            Map.entry("Unhandled exception", "Необработанное исключение"),
            Map.entry("Null Pointer Dereference", "Разыменование null-указателя"),
            Map.entry("SQL Injection", "SQL-инъекция"),
            Map.entry("Cross-Site Scripting (XSS)", "Межсайтовое скриптование (XSS)"),
            Map.entry("Insecure Randomness", "Ненадежная случайность"),
            Map.entry("Insecure Communication (No Encryption)", "Не защищенная коммуникация (без шифрования)"),
            Map.entry("Buffer Overflow", "Переполнение буфера"),
            Map.entry("Improper Input Validation", "Неверная валидация ввода"),
            Map.entry("Command Injection", "Инъекция команд"),
            Map.entry("Insecure Direct Object References (IDOR)", "Небезопасные прямые ссылки на объекты (IDOR)"),
            Map.entry("Cross-Site Request Forgery (CSRF)", "Мошенничество с межсайтовыми запросами (CSRF)"),
            Map.entry("Broken Authentication", "Нарушенная аутентификация"),
            Map.entry("Sensitive Data Exposure", "Разглашение чувствительных данных"),
            Map.entry("Improper Authorization", "Неверная авторизация"),
            Map.entry("Path Traversal", "Путевая уязвимость"),
            Map.entry("Race Condition", "Условие гонки"),
            Map.entry("Privilege Escalation", "Эскалация привилегий"),
            Map.entry("Hardcoded Credentials", "Жестко закодированные учетные данные"),
            Map.entry("Unsecured File Upload", "Не защищенная загрузка файлов"),
            Map.entry("Memory Leak", "Утечка памяти"),
            Map.entry("Improper Error Handling", "Неверная обработка ошибок"),
            Map.entry("Directory Traversal", "Перебор директорий"),
            Map.entry("Weak Password Policy", "Слабая политика паролей"),
            Map.entry("Use of Hardcoded Cryptographic Keys", "Использование жестко закодированных криптографических ключей"),
            Map.entry("Denial of Service (DoS)", "Отказ в обслуживании (DoS)"),
            Map.entry("Improper Session Handling", "Неверная обработка сессий")
    );

    private void addVulnerability(String type, String className, String method) {

        type = VULNERABILITY_TYPES.getOrDefault(type, type);
        vulnerabilitiesByTypeAndClass
                .computeIfAbsent(type, k -> new HashMap<>())
                .computeIfAbsent(className, k -> new HashSet<>())
                .add(method);

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
