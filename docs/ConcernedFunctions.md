# Altered privacy functions

The functions below were altered in the `applet/MLKEMApplet` for testing. 
In case of a practical use of this implementation, we advise to use the `sec_app/MLKEMApplet`. 
This list is to properly document the functions that were exposed in testing.

- `packedDK` (byte[]) - buffer that stores the decapsulation key.
- `secretKey` (byte[]) - buffer that stores the secret key.
- `bufC` (byte[]) - buffer that stores the encapsulation.
- `generateKeys512Internal()` - internal key generation function for ML-KEM-512.
- `generateKeys768Internal()` - internal key generation function for ML-KEM-768.
- `generateKeys1024Internal()` - internal key generation function for ML-KEM-1024.
- `generateKeys512()` - function that generates the key pair for ML-KEM-512.
- `generateKeys768()` - function that generates the key pair for ML-KEM-768.
- `generateKeys1024()` - function that generates the key pair for ML-KEM-1024.
- `encaps512Internal()` - internal function for encapsulating the secret key for ML-KEM-512.
- `encaps768Internal()` - internal function for encapsulating the secret key for ML-KEM-768.
- `encaps1024Internal()` - internal function for encapsulating the secret key for ML-KEM-1024.
- `encaps512()` - function that encapsulates the ML-KEM-512 secret key.
- `encaps768()` - function that encapsulates the ML-KEM-768 secret key.
- `encaps1024()` - function that encapsulates the ML-KEM-1024 secret key.
- `decaps512Internal()` - internal function for decapsulating the ML-KEM-512 secret key.
- `decaps768Internal()` - internal function that decapsulates the ML-KEM-768 secret key.
- `decaps1024Internal()` - internal function that decapsulates the ML-KEM-1024 secret key.
- `decaps512()` - function that decapsulates the ML-KEM-512 secret key.
- `decaps768()` - function that decapsulates the ML-KEM-768 secret key.
- `decaps1024()` - function that decapsulates the ML-KEM-1024 secret key.
