package org.example.mtls.server;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/api")
public class DemoApi {

    @GetMapping("/messages")
    List<String> messages() {
        return List.of("Hello", "World");
    }
}
