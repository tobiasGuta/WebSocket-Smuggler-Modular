package burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLException;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.CancellationException;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorCompletionService;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicBoolean;

public class AttackEngine {

    public interface AttackListener {
        void onAttackStarted(int id, String host, String payload, String timestamp);
        void onAttackComplete(int id, AttackLog log, ResponseAnalyzer.ResponseAnalysis analysis);
        void onAttackError(int id, String errorMessage);
        void onBatchComplete(boolean cancelled);
        void onProgressUpdate(int completed, int total);
    }

    private final MontoyaApi api;
    private final AttackListener listener;
    private final AtomicInteger requestIdCounter = new AtomicInteger(1);
    private final SSLSocketFactory sslSocketFactory;

    private final Object lifecycleLock = new Object();
    private volatile AttackRun currentRun;

    public AttackEngine(MontoyaApi api, AttackListener listener) {
        this.api = api;
        this.listener = listener;
        this.sslSocketFactory = createTrustAllSSLFactory();
    }

    public boolean isRunning() {
        AttackRun run = currentRun;
        return run != null && run.isRunning();
    }

    public boolean isPaused() {
        AttackRun run = currentRun;
        return run != null && run.isPaused();
    }

    public void togglePause() {
        AttackRun run = currentRun;
        if (run == null || !run.isRunning()) {
            api.logging().logToOutput("No running attack to pause.");
            return;
        }

        boolean paused = run.togglePause();
        api.logging().logToOutput(paused ? "Attack Paused." : "Attack Resumed.");
    }

    public void stop() {
        AttackRun run = currentRun;
        if (run != null) {
            run.cancel();
        }
        api.logging().logToOutput("Attack Stopped by User.");
    }

    public void performSingleAttack(HttpRequestResponse baseRequest, AttackConfig config) {
        if (baseRequest == null) return;
        startManagedAttack(baseRequest, config, Collections.singletonList(null), 1);
    }

    public void performWordlistAttack(HttpRequestResponse baseRequest, AttackConfig config,
                                      List<String> wordlist) {
        if (baseRequest == null || wordlist == null || wordlist.isEmpty()) return;

        startManagedAttack(baseRequest, config, wordlist, config.getThreadCount());
    }

    private void startManagedAttack(HttpRequestResponse baseRequest, AttackConfig config,
                                    List<String> payloads, int workerCount) {
        AttackRun run = new AttackRun(Math.max(1, workerCount), payloads.size());
        synchronized (lifecycleLock) {
            if (isRunning()) {
                api.logging().logToOutput("Attack already running.");
                return;
            }
            currentRun = run;
        }

        run.executor.execute(() -> coordinateRun(run, baseRequest, config, payloads));
    }

    private void coordinateRun(AttackRun run, HttpRequestResponse baseRequest, AttackConfig config,
                               List<String> payloads) {
        ExecutorCompletionService<Void> completionService = new ExecutorCompletionService<>(run.executor);
        AtomicInteger completed = new AtomicInteger(0);
        int submitted = 0;

        try {
            for (String payload : payloads) {
                run.awaitIfPaused();
                if (run.isCancelled()) break;

                if (submitWorker(run, completionService, () -> {
                    executeAttack(run, baseRequest, config, payload);
                    if (!run.isCancelled()) {
                        listener.onProgressUpdate(completed.incrementAndGet(), run.total);
                    }
                    return null;
                })) {
                    submitted++;
                }

                sleepDelay(run, config.getRequestDelayMs());
            }

            for (int i = 0; i < submitted && !run.isCancelled(); i++) {
                try {
                    completionService.take().get();
                } catch (ExecutionException e) {
                    if (!run.isCancelled()) {
                        Throwable cause = e.getCause() != null ? e.getCause() : e;
                        api.logging().logToError("Worker thread crashed: " + cause.getMessage());
                        cause.printStackTrace(api.logging().error());
                    }
                }
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            run.cancel();
        } catch (CancellationException ignored) {
            run.cancel();
        } catch (Throwable t) {
            if (!run.isCancelled()) {
                api.logging().logToError("Attack coordinator crashed: " + t.getMessage());
                t.printStackTrace(api.logging().error());
            }
        } finally {
            boolean cancelled = run.isCancelled();
            run.finish();
            synchronized (lifecycleLock) {
                if (currentRun == run) currentRun = null;
            }
            listener.onBatchComplete(cancelled);
            api.logging().logToOutput(cancelled ? "Attack stopped." : "Attack finished.");
        }
    }

    private boolean submitWorker(AttackRun run, ExecutorCompletionService<Void> completionService,
                                 java.util.concurrent.Callable<Void> worker) throws InterruptedException {
        while (!run.isCancelled()) {
            run.awaitIfPaused();
            try {
                completionService.submit(worker);
                return true;
            } catch (RejectedExecutionException e) {
                if (run.executor.isShutdown()) return false;
                Thread.sleep(50);
            }
        }
        return false;
    }

    private void sleepDelay(AttackRun run, int delayMs) throws InterruptedException {
        int remaining = delayMs;
        while (remaining > 0 && !run.isCancelled()) {
            run.awaitIfPaused();
            int sleepMs = Math.min(remaining, 100);
            Thread.sleep(sleepMs);
            remaining -= sleepMs;
        }
    }

    private void executeAttack(AttackRun run, HttpRequestResponse baseRequest, AttackConfig config, String payload)
            throws InterruptedException {
        run.awaitIfPaused();
        if (run.isCancelled()) return;

        int id = requestIdCounter.getAndIncrement();
        String host = baseRequest.httpService().host();
        String connectHost = config.resolveConnectHost(host);
        String sniHost = config.resolveSniHost(host);
        int port = baseRequest.httpService().port();
        boolean isSecure = baseRequest.httpService().secure();
        String timestamp = new SimpleDateFormat("HH:mm:ss").format(new Date());

        listener.onAttackStarted(id, host, payload, timestamp);
        run.awaitIfPaused();
        if (run.isCancelled()) return;

        String fullRequestStr = RequestTemplateBuilder.buildSmugglingRequest(
                baseRequest.request(), host, port, config, payload);

        Socket socket = null;
        try {
            socket = createSocket(run, connectHost, port, isSecure,
                    config.isVerifyTlsCertificates(), sniHost,
                    config.getConnectTimeoutMs(), config.getReadTimeoutMs());

            OutputStream out = socket.getOutputStream();
            InputStream in = socket.getInputStream();

            run.awaitIfPaused();
            if (run.isCancelled()) return;

            out.write(fullRequestStr.getBytes(StandardCharsets.ISO_8859_1));
            out.flush();

            CaptureResult capture = captureResponse(run, socket, in, config);
            if (run.isCancelled()) return;

            byte[] responseBytes = capture.bytes;
            ResponseAnalyzer.ResponseAnalysis analysis = ResponseAnalyzer.analyze(responseBytes, capture.termination);

            HttpRequest burpReq = HttpRequest.httpRequest(baseRequest.httpService(), fullRequestStr);
            HttpResponse burpRes = HttpResponse.httpResponse(ByteArray.byteArray(responseBytes));

            listener.onAttackComplete(id, new AttackLog(burpReq, burpRes, analysis), analysis);

        } catch (SocketTimeoutException ex) {
            if (run.isCancelled()) return;
            listener.onAttackError(id, "Connect timeout: " + ex.getMessage());
            api.logging().logToError("Connect timeout (ID " + id + "): " + ex.getMessage());
        } catch (SSLException ex) {
            if (run.isCancelled()) return;
            listener.onAttackError(id, "TLS error: " + ex.getMessage());
            api.logging().logToError("TLS error (ID " + id + "): " + ex.getMessage());
        } catch (SocketException ex) {
            if (run.isCancelled()) return;
            listener.onAttackError(id, "Socket error: " + ex.getMessage());
            api.logging().logToError("Socket error (ID " + id + "): " + ex.getMessage());
        } catch (Exception ex) {
            if (run.isCancelled()) return;
            listener.onAttackError(id, ex.getMessage());
            api.logging().logToError("Attack error (ID " + id + "): " + ex.getMessage());
        } finally {
            if (socket != null) {
                run.untrackSocket(socket);
                closeQuietly(socket);
            }
        }
    }

    private CaptureResult captureResponse(AttackRun run, Socket socket, InputStream in, AttackConfig config)
            throws IOException, InterruptedException {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream(
                Math.min(config.getMaxCaptureBytes(), 64 * 1024));
        byte[] data = new byte[8192];
        long readDeadline = System.currentTimeMillis() + config.getReadTimeoutMs();

        while (!run.isCancelled()) {
            run.awaitIfPaused();

            int remainingCapacity = config.getMaxCaptureBytes() - buffer.size();
            if (remainingCapacity <= 0) {
                return new CaptureResult(buffer.toByteArray(), ResponseAnalyzer.CaptureTermination.TRUNCATED);
            }

            long remainingReadMs = readDeadline - System.currentTimeMillis();
            if (remainingReadMs <= 0) {
                return new CaptureResult(buffer.toByteArray(), ResponseAnalyzer.CaptureTermination.READ_TIMEOUT);
            }

            int nextTimeoutMs = (int) Math.min(config.getIdleTimeoutMs(), remainingReadMs);
            socket.setSoTimeout(Math.max(1, nextTimeoutMs));

            try {
                int nRead = in.read(data, 0, Math.min(data.length, remainingCapacity));
                if (nRead == -1) {
                    return new CaptureResult(buffer.toByteArray(), ResponseAnalyzer.CaptureTermination.EOF);
                }

                buffer.write(data, 0, nRead);

                if (buffer.size() >= config.getMaxCaptureBytes()) {
                    return new CaptureResult(buffer.toByteArray(), ResponseAnalyzer.CaptureTermination.TRUNCATED);
                }
                if (ResponseAnalyzer.hasSufficientEvidence(buffer.toByteArray())) {
                    return new CaptureResult(buffer.toByteArray(), ResponseAnalyzer.CaptureTermination.EVIDENCE_COMPLETE);
                }
            } catch (SocketTimeoutException e) {
                ResponseAnalyzer.CaptureTermination reason =
                        remainingReadMs <= config.getIdleTimeoutMs()
                                ? ResponseAnalyzer.CaptureTermination.READ_TIMEOUT
                                : ResponseAnalyzer.CaptureTermination.IDLE_TIMEOUT;
                return new CaptureResult(buffer.toByteArray(), reason);
            } catch (SocketException e) {
                if (run.isCancelled()) {
                    return new CaptureResult(buffer.toByteArray(), ResponseAnalyzer.CaptureTermination.ERROR);
                }
                return new CaptureResult(buffer.toByteArray(), ResponseAnalyzer.CaptureTermination.CONNECTION_RESET);
            }
        }

        return new CaptureResult(buffer.toByteArray(), ResponseAnalyzer.CaptureTermination.ERROR);
    }

    private Socket createSocket(AttackRun run, String host, int port, boolean isSecure,
                                boolean verifyTlsCertificates, String sniHost,
                                int connectTimeoutMs, int readTimeoutMs)
            throws IOException {
        // Using raw sockets instead of api.http().sendRequest() to intentionally bypass 
        // Burp's strict HTTP parsing and content-length normalization, which is fundamentally
        // required for protocol smuggling to work.
        Socket socket;
        if (isSecure) {
            SSLSocketFactory factory = verifyTlsCertificates
                    ? (SSLSocketFactory) SSLSocketFactory.getDefault()
                    : sslSocketFactory;
            SSLSocket ssl = (SSLSocket) factory.createSocket();
            socket = ssl;
            run.trackSocket(socket);
            try {
                socket.connect(new InetSocketAddress(host, port), connectTimeoutMs);
                socket.setSoTimeout(readTimeoutMs);
                if (run.isCancelled()) throw new SocketException("Attack cancelled");
                applySni(ssl, sniHost);
                ssl.startHandshake();
                return ssl;
            } catch (IOException e) {
                run.untrackSocket(socket);
                closeQuietly(socket);
                throw e;
            }
        }

        socket = new Socket();
        run.trackSocket(socket);
        try {
            socket.connect(new InetSocketAddress(host, port), connectTimeoutMs);
            socket.setSoTimeout(readTimeoutMs);
            return socket;
        } catch (IOException e) {
            run.untrackSocket(socket);
            closeQuietly(socket);
            throw e;
        }
    }

    private static void applySni(SSLSocket ssl, String sniHost) {
        if (sniHost == null || sniHost.trim().isEmpty()) return;

        try {
            SSLParameters parameters = ssl.getSSLParameters();
            parameters.setServerNames(List.of(new SNIHostName(sniHost.trim())));
            ssl.setSSLParameters(parameters);
        } catch (IllegalArgumentException ignored) {
            // IP literals and some lab hostnames are not valid SNI names; connect without SNI.
        }
    }

    private static void closeQuietly(Socket socket) {
        try {
            socket.close();
        } catch (IOException ignored) {}
    }

    private static class CaptureResult {
        private final byte[] bytes;
        private final ResponseAnalyzer.CaptureTermination termination;

        private CaptureResult(byte[] bytes, ResponseAnalyzer.CaptureTermination termination) {
            this.bytes = bytes;
            this.termination = termination;
        }
    }

    private static class AttackRun {
        private static final AtomicInteger RUN_COUNTER = new AtomicInteger(1);

        private final ThreadPoolExecutor executor;
        private final AtomicBoolean running = new AtomicBoolean(true);
        private final AtomicBoolean cancelled = new AtomicBoolean(false);
        private final Object pauseMonitor = new Object();
        private final Set<Socket> activeSockets = ConcurrentHashMap.newKeySet();
        private final int total;

        private volatile boolean paused = false;

        private AttackRun(int workerCount, int total) {
            int threadCount = workerCount + 1;
            this.total = total;
            this.executor = new ThreadPoolExecutor(
                    threadCount,
                    threadCount,
                    0L,
                    TimeUnit.MILLISECONDS,
                    new ArrayBlockingQueue<>(Math.max(1, workerCount)),
                    r -> {
                        Thread t = new Thread(r, "WS-Smuggler-Run-" + RUN_COUNTER.getAndIncrement());
                        t.setDaemon(true);
                        return t;
                    },
                    new ThreadPoolExecutor.AbortPolicy()
            );
        }

        private boolean isRunning() {
            return running.get();
        }

        private boolean isPaused() {
            return paused;
        }

        private boolean isCancelled() {
            return cancelled.get();
        }

        private boolean togglePause() {
            synchronized (pauseMonitor) {
                paused = !paused;
                if (!paused) pauseMonitor.notifyAll();
                return paused;
            }
        }

        private void awaitIfPaused() throws InterruptedException {
            synchronized (pauseMonitor) {
                while (paused && !cancelled.get()) {
                    pauseMonitor.wait(200);
                }
            }
            if (cancelled.get()) throw new CancellationException("Attack cancelled");
        }

        private void cancel() {
            if (!cancelled.compareAndSet(false, true)) return;
            synchronized (pauseMonitor) {
                paused = false;
                pauseMonitor.notifyAll();
            }
            closeActiveSockets();
            executor.shutdownNow();
        }

        private void finish() {
            running.set(false);
            synchronized (pauseMonitor) {
                paused = false;
                pauseMonitor.notifyAll();
            }
            closeActiveSockets();
            executor.shutdown();
        }

        private void trackSocket(Socket socket) {
            activeSockets.add(socket);
            if (cancelled.get()) closeQuietly(socket);
        }

        private void untrackSocket(Socket socket) {
            activeSockets.remove(socket);
        }

        private void closeActiveSockets() {
            for (Socket socket : activeSockets) {
                closeQuietly(socket);
            }
            activeSockets.clear();
        }
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
