// A deliberately insecure Kotlin file used to demonstrate `security_scan`.
// It contains NO real secrets — only code *patterns* the analyzer flags.

import java.io.File
import java.security.SecureRandom
import javax.crypto.spec.SecretKeySpec

class VulnerableSample {

    // Hardcoded key material: the AES key is baked into the source instead of
    // coming from a KeyStore or secret manager. (HardcodedAesKey)
    fun cipherKey(): SecretKeySpec =
        SecretKeySpec("0123456789abcdef".toByteArray(), "AES")

    // Predictable temp location in /tmp: any local user can guess/pre-create it.
    // (PredictableTempFile)
    fun scratchFile(): File = File("/tmp/session-data.txt")

    // Seeding SecureRandom with a fixed value makes its output predictable,
    // defeating the whole point of a CSPRNG. (InsecureRandomSeed)
    fun token(): SecureRandom = SecureRandom(byteArrayOf(1, 2, 3, 4))
}
