package ru.symbolexec.SymbolicExec.core;

import com.microsoft.z3.*;
import com.github.javaparser.JavaParser;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.visitor.VoidVisitorAdapter;
import org.jf.dexlib2.dexbacked.DexBackedDexFile;
import org.jf.dexlib2.dexbacked.DexBackedMethodImplementation;
import org.jf.dexlib2.iface.ClassDef;
import org.jf.dexlib2.iface.Method;
import org.jf.dexlib2.iface.instruction.Instruction;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;

public class SymbolicExecution {

    // Метод для анализа исходных Java файлов
    public void analyzeJavaFile(File javaFile) {
        try {
            // Чтение файла Java
            String code = new String(Files.readAllBytes(javaFile.toPath()));

            // Используем JavaParser для парсинга кода
            JavaParser javaParser = new JavaParser();
            CompilationUnit compilationUnit = javaParser.parse(code).getResult().orElseThrow(() -> new RuntimeException("Invalid Java code"));

            // Перебор всех методов в коде
            compilationUnit.accept(new VoidVisitorAdapter<Void>() {
                @Override
                public void visit(MethodDeclaration method, Void arg) {
                    super.visit(method, arg);
                    System.out.println("Found method: " + method.getName());
                }
            }, null);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Основной метод анализа DEX-файла
    public String analyzeDex(File dexFile) throws Exception {
        // Чтение содержимого DEX-файла в массив байтов
        byte[] dexBytes = Files.readAllBytes(dexFile.toPath());
        DexBackedDexFile dexBackedDexFile = new DexBackedDexFile(null, dexBytes);

        // Создание контекста Z3
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

                // Если файл содержит исходный код Java, добавим анализ с использованием javaparser
                File javaFile = new File(className + ".java");  // Здесь предполагаем, что у нас есть Java исходники
                if (javaFile.exists()) {
                    analyzeJavaFile(javaFile);  // Анализируем Java файл с помощью javaparser
                }
            }
        }

        // Проверка наличия уязвимостей
        if (solver.check() == Status.SATISFIABLE) {
            return "Vulnerabilities Found!";
        }
        return "No vulnerabilities detected.";
    }

    // Метод для анализа инструкций конкретного метода
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
