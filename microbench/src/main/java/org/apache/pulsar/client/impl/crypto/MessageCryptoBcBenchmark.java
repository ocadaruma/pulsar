package org.apache.pulsar.client.impl.crypto;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HashSet;
import java.util.Map;
import java.util.Random;
import java.util.Set;

import org.apache.pulsar.client.api.CryptoKeyReader;
import org.apache.pulsar.client.api.EncryptionKeyInfo;
import org.apache.pulsar.client.api.PulsarClientException;
import org.apache.pulsar.common.api.proto.MessageMetadata;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Fork;
import org.openjdk.jmh.annotations.Measurement;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.Warmup;

@Fork(1)
@Warmup(iterations = 1)
@Measurement(iterations = 2)
@BenchmarkMode(Mode.Throughput)
public class MessageCryptoBcBenchmark {
    public static class EncKeyReader implements CryptoKeyReader {
        EncryptionKeyInfo keyInfo = new EncryptionKeyInfo();

        @Override
        public EncryptionKeyInfo getPublicKey(String keyName, Map<String, String> keyMeta) {
            Path path = Paths.get("./microbench/src/main/resources/certificate/public-key." + keyName);
            if (Files.isReadable(path)) {
                try {
                    keyInfo.setKey(Files.readAllBytes(path));
                    return keyInfo;
                } catch (IOException e) {
                    throw new UncheckedIOException(e);
                }
            } else {
                throw new RuntimeException("Certificate file " + path + " is not present or not readable.");
            }
        }

        @Override
        public EncryptionKeyInfo getPrivateKey(String keyName, Map<String, String> keyMeta) {
            return null;
        }
    }

    @State(Scope.Benchmark)
    public abstract static class BenchmarkStateBase {
        private static final int SIZE = 32 * 1024;

        final MessageCryptoBc crypto;
        final ByteBuffer payload;
        final ByteBuffer encryptedBuffer;
        final CryptoKeyReader keyReader;
        final Set<String> encryptionKeys;

        BenchmarkStateBase(String provider) {
            crypto = new MessageCryptoBc("test", true, provider);
            keyReader = new EncKeyReader();
            payload = ByteBuffer.allocate(SIZE);
            encryptedBuffer = ByteBuffer.allocate(crypto.getMaxOutputSize(SIZE));
            Random rnd = new Random(0);
            rnd.nextBytes(payload.array());

            encryptionKeys = new HashSet<>();
            encryptionKeys.add("client-ecdsa.pem");
        }
    }

    public static class BcState extends BenchmarkStateBase {
        public BcState() {
            super("BC");
        }
    }

    public static class SunJceState extends BenchmarkStateBase {
        public SunJceState() {
            super("SunJCE");
        }
    }

    @Benchmark
    public void encryptBc(BcState state) {
        try {
            state.encryptedBuffer.clear();
            state.crypto.encrypt(
                    state.encryptionKeys,
                    state.keyReader,
                    MessageMetadata::new,
                    state.payload.duplicate(),
                    state.encryptedBuffer);
        } catch (PulsarClientException e) {
            throw new RuntimeException(e);
        }
    }

    @Benchmark
    public void encryptSunJCE(SunJceState state) {
        try {
            state.encryptedBuffer.clear();
            state.crypto.encrypt(
                    state.encryptionKeys,
                    state.keyReader,
                    MessageMetadata::new,
                    state.payload.duplicate(),
                    state.encryptedBuffer);
        } catch (PulsarClientException e) {
            throw new RuntimeException(e);
        }
    }
}
