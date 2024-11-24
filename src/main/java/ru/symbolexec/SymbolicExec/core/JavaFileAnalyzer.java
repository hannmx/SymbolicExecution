package ru.symbolexec.SymbolicExec.core;

import com.github.javaparser.JavaParser;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.visitor.VoidVisitorAdapter;

import java.io.File;
import java.nio.file.Files;

public class JavaFileAnalyzer {

    /**
     * Анализирует Java-файл, проверяя глубину вложенности методов.
     * @param javaFile Java-файл для анализа.
     */
    public void analyzeJavaFile(File javaFile) {
        try {
            // Чтение исходного кода из файла
            String code = new String(Files.readAllBytes(javaFile.toPath()));
            CompilationUnit compilationUnit = new JavaParser().parse(code).getResult()
                    .orElseThrow(() -> new RuntimeException("Ошибка парсинга Java файла: " + javaFile.getName()));

            // Перебираем методы в файле и анализируем их
            compilationUnit.accept(new VoidVisitorAdapter<Void>() {
                @Override
                public void visit(MethodDeclaration method, Void arg) {
                    super.visit(method, arg);

                    // Проверяем, есть ли тело метода
                    if (method.getBody().isPresent()) {
                        int nestingDepth = calculateNestingDepth(method.getBody().get().toString());
                        if (nestingDepth > 3) {
                            System.out.println("Высокая вложенность в методе: " + method.getName());
                        }
                    }
                }
            }, null);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * Рассчитывает максимальную глубину вложенности кода.
     * @param code Код для анализа.
     * @return Глубина вложенности.
     */
    private int calculateNestingDepth(String code) {
        int depth = 0, maxDepth = 0;
        for (char c : code.toCharArray()) {
            if (c == '{') depth++;
            if (c == '}') depth--;
            maxDepth = Math.max(maxDepth, depth);
        }
        return maxDepth;
    }
}
