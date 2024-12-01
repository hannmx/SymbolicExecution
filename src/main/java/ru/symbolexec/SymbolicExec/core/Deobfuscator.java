package ru.symbolexec.SymbolicExec.core;

import jadx.api.JadxDecompiler;
import jadx.api.JavaClass;
import jadx.api.JadxArgs;

import java.io.File;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

public class Deobfuscator {

    private final JadxDecompiler jadxDecompiler;
    private final Map<String, String> nameMapping = new HashMap<>();

    // Конструктор Deobfuscator принимает файл APK
    public Deobfuscator(File apkFile) throws IOException {
        // Создаем объект для настройки параметров анализа
        JadxArgs args = new JadxArgs();
        args.getInputFiles().add(apkFile); // Добавляем APK файл для анализа

        // Создаем экземпляр JadxDecompiler с параметрами
        this.jadxDecompiler = new JadxDecompiler(args);

        // Загружаем и анализируем APK файл
        jadxDecompiler.load(); // Используем метод load() с настройками

        // Инициализируем маппинг имен
        populateNameMapping();
    }

    // Метод для преобразования имени из DEX формата в Java формат
    private String dexToJavaName(String dexName) {
        if (dexName.startsWith("L") && dexName.endsWith(";")) {
            dexName = dexName.substring(1, dexName.length() - 1);
        }
        return dexName.replace("/", ".");
    }

    // Метод для преобразования имени из Java формата в DEX формат
    private String javaToDexName(String javaName) {
        return "L" + javaName.replace(".", "/") + ";";
    }

    // Инициализация маппинга имен
    private void populateNameMapping() {
        for (JavaClass javaClass : jadxDecompiler.getClasses()) {
            String javaClassName = javaClass.getFullName();
            String dexClassName = javaToDexName(javaClassName);

            // Добавляем соответствие для имени класса
            nameMapping.put(javaClassName, javaClassName);
            nameMapping.put(dexClassName, javaClassName);

            for (var method : javaClass.getMethods()) {
                String methodName = method.getName();
                String fullJavaMethodName = javaClassName + ":" + methodName;
                String fullDexMethodName = dexClassName + ":" + methodName;

                // Добавляем соответствие для метода
                nameMapping.put(fullJavaMethodName, fullJavaMethodName);
                nameMapping.put(fullDexMethodName, fullJavaMethodName);
            }
        }
    }

    // Метод для деобфускации имен классов и методов
    public String deobfuscateClassAndMethod(String obfuscatedName) {
        return nameMapping.getOrDefault(obfuscatedName, obfuscatedName);
    }

    // Метод для проверки (вывода) всех доступных маппингов
    public void printNameMappings() {
        System.out.println("Список маппингов имен:");
        nameMapping.forEach((key, value) -> System.out.println(key + " -> " + value));
    }

    // Закрытие ресурса JadxDecompiler, если это требуется
    public void close() {
        jadxDecompiler.close();
    }
}
