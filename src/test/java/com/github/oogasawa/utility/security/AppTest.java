package com.github.oogasawa.utility.security;

import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestMethodOrder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


@DisplayName("a trivial test")
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class AppTest {

    private static final Logger logger = LoggerFactory.getLogger(AppTest.class.getName());
    
    @Test
    @Order(1)
    public void trivialTest() {
        assertTrue(true);
    }

}
