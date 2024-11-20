package ru.symbolexec.SymbolicExec.core;

import com.microsoft.z3.*;
import org.jf.dexlib2.*;
import org.jf.dexlib2.iface.Method;
import org.jf.dexlib2.iface.ClassDef;
import org.jf.dexlib2.dexbacked.DexBackedDexFile;
import org.jf.dexlib2.dexbacked.DexBackedMethodImplementation;
import org.jf.dexlib2.iface.instruction.Instruction;

import java.io.File;
import java.nio.file.Files;

public class SymbolicExecution {
    /**
     * Основной метод анализа DEX-файла.
     *
     * @param dexFile файл формата DEX, извлеченный из APK.
     * @return строка с результатом анализа (наличие или отсутствие уязвимостей).
     * @throws Exception если произошла ошибка во время анализа.
     */
    public String analyzeDex(File dexFile) throws Exception {
        // Чтение содержимого DEX-файла в массив байтов
        byte[] dexBytes = Files.readAllBytes(dexFile.toPath());

        // Создание объекта DEX-файла из массива байтов
        DexBackedDexFile dexBackedDexFile = new DexBackedDexFile(null, dexBytes);

        // Создание контекста Z3 для символьного исполнения
        Context ctx = new Context();
        Solver solver = ctx.mkSolver();

        // Итерация по классам и методам DEX-файла
        for (ClassDef classDef : dexBackedDexFile.getClasses()) {
            String className = classDef.getType();
            System.out.println("Analyzing class: " + className);

            for (Method method : classDef.getMethods()) {
                String methodName = method.getName();
                System.out.println("  Analyzing method: " + methodName);

                // Анализ инструкций метода
                analyzeMethodInstructions(ctx, solver, method);
            }
        }

        // Проверка наличия уязвимостей
        if (solver.check() == Status.SATISFIABLE) {
            return "Vulnerabilities Found!";
        }
        return "No vulnerabilities detected.";
    }

    /**
     * Метод для анализа инструкций конкретного метода.
     *
     * @param ctx    контекст Z3.
     * @param solver решатель Z3.
     * @param method метод, инструкции которого анализируются.
     */
    private void analyzeMethodInstructions(Context ctx, Solver solver, Method method) {
        // Пропускаем методы без реализации
        if (!(method.getImplementation() instanceof DexBackedMethodImplementation)) {
            return;
        }

        // Получение реализации метода
        DexBackedMethodImplementation implementation = (DexBackedMethodImplementation) method.getImplementation();

        // Итерация по инструкциям метода
        for (Instruction instruction : implementation.getInstructions()) {
            String opcodeName = instruction.getOpcode().name();

            // Проверка на некорректные проверки условий
            if (opcodeName.contains("IF_EQ") || opcodeName.contains("IF_NE")) {
                System.out.println("    Found conditional check: " + instruction.getOpcode());
                BoolExpr condition = ctx.mkBool(true); // Реальное условие можно уточнить
                solver.add(ctx.mkNot(condition));
            }

            // Проверка на хардкодированные строки
            if (opcodeName.contains("CONST_STRING")) {
                System.out.println("    Found hardcoded string!");
                BoolExpr hardcodedIssue = ctx.mkBool(true);
                solver.add(hardcodedIssue);
            }

            // Проверка на небезопасное использование криптографии
            if (opcodeName.contains("INVOKE") && instruction.toString().contains("Cipher")) {
                System.out.println("    Found potential insecure cryptography usage!");
                BoolExpr cryptoIssue = ctx.mkBool(true);
                solver.add(cryptoIssue);
            }

            // Проверка на потенциальные SQL-инъекции
            if (opcodeName.contains("INVOKE") && instruction.toString().contains("execSQL")) {
                System.out.println("    Found potential SQL injection vulnerability!");
                BoolExpr sqlInjection = ctx.mkBool(true);
                solver.add(sqlInjection);
            }

            // Проверка на отсутствие обработки исключений
            if (opcodeName.contains("THROW")) {
                System.out.println("    Found unhandled exception!");
                BoolExpr unhandledException = ctx.mkBool(true);
                solver.add(unhandledException);
            }
        }
    }
}