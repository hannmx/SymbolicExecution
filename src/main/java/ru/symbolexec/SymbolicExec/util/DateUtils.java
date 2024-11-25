package ru.symbolexec.SymbolicExec.util;

import java.time.format.DateTimeFormatter;
import java.time.LocalDateTime;

public class DateUtils {
    public static String format(LocalDateTime dateTime, String pattern) {
        return dateTime.format(DateTimeFormatter.ofPattern(pattern));
    }
}
