package ru.symbolexec.SymbolicExec.util;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class ThymeleafConfig {
    @Bean(name = "dateUtils")
    public DateUtils dateUtils() {
        return new DateUtils();
    }
}
