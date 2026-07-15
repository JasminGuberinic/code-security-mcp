// A deliberately insecure Java file used to demonstrate Java `security_scan`.
// It contains NO real secrets — only code patterns SpotBugs + FindSecBugs flag.
//
// NOTE: SpotBugs analyzes *compiled bytecode*, so build this first, e.g.:
//   javac -d classes examples/VulnerableSample.java
// then scan the "classes" directory.

import java.security.MessageDigest;
import javax.crypto.Cipher;

public class VulnerableSample {

    // MD5 is a broken hash for security use. (WEAK_MESSAGE_DIGEST_MD5)
    public MessageDigest weakHash() throws Exception {
        return MessageDigest.getInstance("MD5");
    }

    // DES + implicit ECB mode: weak cipher, no integrity. (DES_USAGE / ECB_MODE)
    public Cipher weakCipher() throws Exception {
        return Cipher.getInstance("DES");
    }
}
