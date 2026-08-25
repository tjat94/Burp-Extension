import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.handler.*;
import burp.api.montoya.logging.Logging;
import javax.crypto.Cipher;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.core.JsonProcessingException;

public class BurpCypher implements BurpExtension, HttpHandler {

    private Logging logging;
    private String serverPrivateKey = """
            -----BEGIN PRIVATE KEY-----
            MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC/CmDZoFEtP1F+
            2VwTxCdyZiLbB4tPQScfBcOwATgD/O9HV1P1fikUis1dWdMqUirxEEyKXKhOfcYd
            SAmgUcYZ2pl+cIIfF/QhVfY2GliLUepl5c0KCpjgW0wf1a+NgQfb+3CFSe/KZPx6
            AbdznRqlPyxOwmuFaLYz6WFDbJhcZ5xkeAAzsR11q+nJMR0zDXGEh540ejVDE+OK
            LX50khTyIgnwXc1C26RN78RDJOMkbHuoPFWhs76eOeet6p2odno+pgP/qOWb2bJe
            1S4lCqDExbBvEk25LkDL0lBJEYR/AS6Ake4oS6h8l1ORb8+Jsb0bfNrCzg2GZyjy
            vDn2PWttAgMBAAECggEAQ8Mco1TYNmJ1N7dFj8VN8KgFyQceBNipVbmntbBY/CEl
            hnqVT0iWrbCmM2x/GE3Y6XTMkW9YS68VLKG2uGUJDXaaZ1zk6r6GW6SwFnS134UI
            zWf7mIo1u67mi4wyHtEbxo2jVcPqCDJV07j0J1AceWy0/KK9nK6NolAvrcjBKlUA
            F9PIOzwS7tlmoX6tN7X8xKcoTwa+W/2poFZFlsBrWDlrQO0+mnIu/ne/nTlBZHIR
            53n4Qg+G7bxs3xKp5DJ9T+K8hd/4iv2zYLBqC1T3WmdNWHD7CDFP4D4GJw9sqoWO
            IYxI8GjJn+jWN6pUvSIHu0HFTOpieJl/v+Hc/FSlCQKBgQD4NEFLiu4eo9ZNk4I2
            a/x8Ixi/NroDhEqtYutdn7IH+IEol7nTtEKkRrA1Z7FMnYh1/1iRQwms8YIr9KsG
            3GeFCGNP8g+9YZ8aXIEU11gML8T+jpN2Y3z7mqRnJIzDeOzPiMYmaopmyKcP7RYS
            L+h2fdjYJtxFu8D3C3ZZS4WXkwKBgQDFCnxZWmoT0lZakIBJwUhH4VtYl0FmxioJ
            +HpLJyO7vR3V46igmarvU3KW+U7ouoYf2lDcfLWOK3VXpW5FpXzp3WNRe7KA70vQ
            QeVTV8vKtIOBfXz5jJNhlm5Dp5iDgfgr4Q+zbR+RjxXLPwc02AbZWyx+q4q1dKmr
            zFcdJWzQ/wKBgQCnO6Ym/RPVxzQ0jsf0XSwAhDE/XONWTUN3sae+LERrBHAZ5qkJ
            UHJ6dzpwsU4PvjDcuFB3h4C0awD3FuJJPCXvx6gKjKE4S9dEjsFWRoYHqAQGNBB9
            eykR6a8N492IMyjz6EcCSVS5Tkbp/yeY13i8pax+byiJP6kTi0CRh8YaSwKBgQCh
            fQaM9N0bgbfkYanCyPZEcx46bTzczmyF32/bSCixJT3enscFWOwPWYUA1zMk6joi
            wPqkulDSRCvXuW23BvppcViE36xcn8Ky3E7nD32mlGtzJTXYEK55vKCCMkl8/ng2
            /i2wEC9fTLW/7dgqJyL14ROGfXEhZovokYCUEqgsYQKBgG4bMelGkTgiGPLc2g7c
            TvAc9T7XlUkRqS5ZvoulZuJsJ2BfnDtYjzzVlRU35kDzEBja0Rkv9Rwys+Ft47Md
            CEaGB/Nz8hBvA3wQjpLYUW4HXul3j5igRvZ/u8CwW+YDqkMpoCcYqTFJnqDOx8I9
            KmaZV/MVPurxIhmwtUrMOjzH
            -----END PRIVATE KEY-----
            """;

    public String clientPublicKey = """
            -----BEGIN PUBLIC KEY-----
            MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAhxYZMHH4GTVQ3iqIC2M0
            Ek06/MIAou1jXqanjLk00lyF9tkm85Sv4GJSrTzz8YticwpH2vVZ0y7E3dzOGQC+
            ndK36Ny9Cif0ijD6vFZxlff8uWBsj5oGxNQ8vEdpZT9JuRrjuIIgKGoWV3jx7D24
            TcbULjVvxIhinGWs+RkByCxEJNv9Gc6k9Hv/I0DJY6Z2zFKBinuMoU+CRkBge8O8
            D7UKRYQ3AEnLVDvI923Di/Lcqz31HKTSha5EjWNF09YKpzrintvWD9GJwt2xP5uV
            D5+2rQcT/+Ba1UWkLzNkvbWvrWYg1OYz/sVN7AZjC5WQcmOSohHlBpLxMxY32jB4
            oQIDAQAB
            -----END PUBLIC KEY-----
            """;

    public String serverPublicKey = """
            -----BEGIN PUBLIC KEY-----
            MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvwpg2aBRLT9RftlcE8Qn
            cmYi2weLT0EnHwXDsAE4A/zvR1dT9X4pFIrNXVnTKlIq8RBMilyoTn3GHUgJoFHG
            GdqZfnCCHxf0IVX2NhpYi1HqZeXNCgqY4FtMH9WvjYEH2/twhUnvymT8egG3c50a
            pT8sTsJrhWi2M+lhQ2yYXGecZHgAM7EddavpyTEdMw1xhIeeNHo1QxPjii1+dJIU
            8iIJ8F3NQtukTe/EQyTjJGx7qDxVobO+njnnreqdqHZ6PqYD/6jlm9myXtUuJQqg
            xMWwbxJNuS5Ay9JQSRGEfwEugJHuKEuofJdTkW/PibG9G3zaws4Nhmco8rw59j1r
            bQIDAQAB
            -----END PUBLIC KEY-----
            """;

    private String clientPrivateKey = """
            -----BEGIN PRIVATE KEY-----
            MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCHFhkwcfgZNVDe
            KogLYzQSTTr8wgCi7WNepqeMuTTSXIX22SbzlK/gYlKtPPPxi2JzCkfa9VnTLsTd
            3M4ZAL6d0rfo3L0KJ/SKMPq8VnGV9/y5YGyPmgbE1Dy8R2llP0m5GuO4giAoahZX
            ePHsPbhNxtQuNW/EiGKcZaz5GQHILEQk2/0ZzqT0e/8jQMljpnbMUoGKe4yhT4JG
            QGB7w7wPtQpFhDcASctUO8j3bcOL8tyrPfUcpNKFrkSNY0XT1gqnOuKe29YP0YnC
            3bE/m5UPn7atBxP/4FrVRaQvM2S9ta+tZiDU5jP+xU3sBmMLlZByY5KiEeUGkvEz
            FjfaMHihAgMBAAECggEAAMiqAvD721dW47Gh7EU+L/Of1afxZ5CeoaXQWcOoutZh
            qn5tRHdAv6HJbJb6nESKkMvi0apoG+6g4r/PaDer63v1sEuw2v9jKta8uzlaD5B+
            uGOG4LzQSI3J2A625dEImjLlxrAmXC6sqFN3zaboaAbg+/9IUabYEePRBYlhpEv7
            jP9IquO6pO3q13gDhot0fS7MM4sTfYKdPfb8qEwYCpsz3Qi7lFdbBqZxz/O/tkPq
            giNJNJnHBLmXNOIdSCocMldIhZaPMmcDODPXAehmrru7l/Kh5hnfdK7Njcoph5T4
            EJqAPOU7XVSyBeJKiKj1x/S+2jzLn8s3hOKCiBbbwQKBgQC+IvSbRXVA16he1yBE
            183VRAALdVRDDTZcFALaexuNfly2SMU9SL/AAFrbNMaQ83y79XtAbDqk8C6YRhyi
            z2Il9puVu8G61UB2lWzD5DvDYbb4OS+AroluYZQzeR1+02sZUkR4R0QnfNRQUtMR
            3awfBIgf9B6Kr90Dnn/OLmQrYQKBgQC14V2azqz4Nkg4bg1LLk612H2fhwz38Evj
            mlMmxAxdIqGJUz+wGb3tSGmGz7fPxmIga9k8n22nMpfZOyyGF9D93LVa+/9NeFEV
            DWH5yph+xBN7SSyQMb+Q1xD6gTigLmkIynUXzcucgZB8oUGtexR2IoFu3Li7R9F3
            HYpUpsKVQQKBgQCFB3X20TEJbhm6SW+lWwwDY7FYUv3ib/MRl1qrvCh55eg+DUoa
            57RpRJZM+m7XadRiuY1DdLXPQtCG778HVmvIPfN7XsNb0eppTYCsyhnaSJq4r2IB
            +ZvkI9eJ7/poCsnLDJklQk94BUmS7XAJ9vt/NC99k9JunD7ZUmL/QcwJ4QKBgQCG
            a812gJEt0VCHBC8nBU5+70XJBVL8W8h6qrAR0osguluQ1soXKK9KE16KmDJNiV00
            gQDI4Tt1etrnXeiGIkv/k4Mlf2EsrGOgn4dtyeHyro+HaolY+KuQLKMLwT1MhYBz
            Us4/jYWSYd+bfMLBqFlzBgWLHe4Z2/ZfhqGZ9rWRAQKBgGX7uHz9nUaldXxt4lBn
            94FR8D6FJxyKGr0/35XrPE3gc1nDJIQGl62E9vk8eVuBsFgqhm2ISroRSxeRI6ml
            djzuBNJ/gQ5hxhj7ifv1ZakiwvxR2D5uJBPU5gve19Fyrq5On6R+KvVR4b+vcZ5A
            0HuYuUaGZhtLd9ouH49CvSXj
            -----END PRIVATE KEY-----
            """;

    @Override
    public void initialize(MontoyaApi api) {
        this.logging = api.logging();
        api.extension().setName("Burp Cypher");

        // Register the HTTP request handler
        api.http().registerHttpHandler(this);
        logging.logToOutput("Extension Loaded Successfully");
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {
        String requestBody = requestToBeSent.body().toString();
        try{
            ObjectMapper mapper = new ObjectMapper();
            JsonNode json = mapper.readTree(requestBody);
            String data = json.path("data").asText("");
            logging.logToOutput("Data: " + requestBody);
            if (!data.isEmpty()) {
                try {
                    byte[] encryptedData = Base64.getDecoder().decode(data);

                    // Decrypt RSA encrypted data
                    byte[] decryptedBytes = decryptRSA(encryptedData, serverPrivateKey);
                    String decryptedData = new String(decryptedBytes, StandardCharsets.UTF_8).trim();

                    // Log fully decoded request
                    logging.logToOutput("\n===== [Decrypted Request] =====");
                    logging.logToOutput(decryptedData);
                    logging.logToOutput("========================================\n");

                } catch (Exception e) {
                    logging.logToError("Request decryption failed: " + e.getMessage());
                }
            }
        } catch (JsonProcessingException e) {
            e.printStackTrace();
        }
        return RequestToBeSentAction.continueWith(requestToBeSent);
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {
        String responseBody = responseReceived.body().toString();
        logging.logToOutput("Response: " +responseBody);
        try{
            ObjectMapper mapper = new ObjectMapper();
            JsonNode json = mapper.readTree(responseBody);
            String data = json.path("data").asText("");
            if (!data.isEmpty()) {
                try {
                    // Decode and decrypt response
                    byte[] encryptedData = Base64.getDecoder().decode(data);
                    byte[] decryptedResponseBytes = decryptRSA(encryptedData, clientPrivateKey);
                    String decryptedResponse = new String(decryptedResponseBytes, StandardCharsets.UTF_8).trim();

                    // Log fully decoded response
                    logging.logToOutput("\n===== [Decrypted Response] =====");
                    logging.logToOutput(decryptedResponse);
                    logging.logToOutput("========================================\n");

                } catch (Exception e) {
                    logging.logToError("Response decryption failed: " + e.getMessage());
                }
            }
            
        } catch (JsonProcessingException e) {
            e.printStackTrace();
        }

        String responseText = "Login successful";

        // Plaintext -> bytes
        byte[] plaintext = responseText.getBytes(StandardCharsets.UTF_8);

        try {
            // Encrypt with client's public key
            byte[] encryptedBytes = encryptRSA(plaintext, clientPublicKey);
            // RSA ciphertext -> Base64 string
            String encryptedData = Base64.getEncoder().encodeToString(encryptedBytes);
            // Create JSON
            ObjectMapper mapper = new ObjectMapper();
            ObjectNode json = mapper.createObjectNode();
            json.put("data", encryptedData);

            String responseJson = mapper.writeValueAsString(json);

            // Replace HTTP response body
            return ResponseReceivedAction.continueWith(responseReceived.withBody(responseJson));
        } catch (Exception e) {
            logging.logToError("Response creation failed: " + e.getMessage());
        }
        return ResponseReceivedAction.continueWith(responseReceived);
    }

    private byte[] decryptRSA(byte[] encryptedData, String privateKeyPem) throws Exception {
        String key = privateKeyPem
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s+", "");

        byte[] keyBytes = Base64.getDecoder().decode(key);

        PrivateKey privateKey = KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(keyBytes));

        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);

        return cipher.doFinal(encryptedData);
    }

    private byte[] encryptRSA(byte[] data, String publicKeyPem) throws Exception {
        String key = publicKeyPem
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s+", "");

        byte[] keyBytes = Base64.getDecoder().decode(key);

        PublicKey publicKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(keyBytes));

        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);

        return cipher.doFinal(data);
    }
}