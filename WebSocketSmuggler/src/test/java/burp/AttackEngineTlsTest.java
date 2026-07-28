package burp;

import org.junit.jupiter.api.Test;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.SSLSocket;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AttackEngineTlsTest {

    @Test
    void enablesHttpsEndpointIdentificationWhenTlsVerificationIsEnabled() throws Exception {
        SSLSocket socket = unconnectedSslSocket();

        AttackEngine.applyTlsParameters(socket, "target.example.com", true);

        assertEquals("HTTPS", socket.getSSLParameters().getEndpointIdentificationAlgorithm());
        assertEquals(1, socket.getSSLParameters().getServerNames().size());
        assertInstanceOf(SNIHostName.class, socket.getSSLParameters().getServerNames().get(0));
    }

    @Test
    void doesNotEnableHostnameVerificationWhenInvalidCertificatesAreAllowed() throws Exception {
        SSLSocket socket = unconnectedSslSocket();

        AttackEngine.applyTlsParameters(socket, "target.example.com", false);

        assertNull(socket.getSSLParameters().getEndpointIdentificationAlgorithm());
    }

    @Test
    void skipsSniForIpAddressesButStillAllowsHostnameVerification() throws Exception {
        SSLSocket socket = unconnectedSslSocket();

        AttackEngine.applyTlsParameters(socket, "192.0.2.10", true);

        assertEquals("HTTPS", socket.getSSLParameters().getEndpointIdentificationAlgorithm());
        assertTrue(socket.getSSLParameters().getServerNames() == null
                || socket.getSSLParameters().getServerNames().isEmpty());
    }

    @Test
    void usesConfiguredIdentityHostInsteadOfConnectHostForTlsLayering() {
        assertEquals("target.example.com",
                AttackEngine.tlsIdentityHost("target.example.com", "192.0.2.10"));
        assertEquals("192.0.2.10",
                AttackEngine.tlsIdentityHost("", "192.0.2.10"));
    }

    private static SSLSocket unconnectedSslSocket() throws Exception {
        return (SSLSocket) SSLContext.getDefault().getSocketFactory().createSocket();
    }
}
