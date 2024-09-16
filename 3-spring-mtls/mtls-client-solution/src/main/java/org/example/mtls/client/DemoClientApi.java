package org.example.mtls.client;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.web.client.RestClientSsl;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.ResponseErrorHandler;
import org.springframework.web.client.RestClient;
import org.springframework.web.server.ResponseStatusException;

import java.io.IOException;

@RestController
@RequestMapping("/")
public class DemoClientApi {

    private static final Logger LOGGER = LoggerFactory.getLogger(DemoClientApi.class);
    private final RestClient restClient;

    public DemoClientApi(RestClient.Builder restClientBuilder, RestClientSsl restClientSsl) {
        this.restClient = restClientBuilder
                .baseUrl("https://localhost:8443")
                .apply(restClientSsl.fromBundle("client"))
                .build();
    }

    @GetMapping
    public ResponseEntity<String> hello() {
        try {
            String result = restClient
                    .get()
                    .uri("/api/messages")
                    .retrieve()
                    .onStatus(new ResponseErrorHandler() {
                        @Override
                        public boolean hasError(ClientHttpResponse response) throws IOException {
                            return response.getStatusCode().is4xxClientError() || response.getStatusCode().is5xxServerError();
                        }

                        @Override
                        public void handleError(ClientHttpResponse response) throws IOException {
                            LOGGER.error("Error {}", response.getStatusCode());
                            throw new ResponseStatusException(response.getStatusCode(), response.getStatusText());
                        }
                    })
                    .body(String.class);
            return ResponseEntity.ok(result);
        } catch (ResponseStatusException ex) {
            return ResponseEntity.status(ex.getStatusCode()).body(ex.getMessage());
        } catch (Exception ex) {
            return ResponseEntity.status(HttpStatusCode.valueOf(500)).body(ex.getMessage());
        }
    }

}
