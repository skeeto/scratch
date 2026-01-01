# $ uv run --with=wasmtime monocypher.py
import functools
import importlib.resources
import secrets
import wasmtime

class Monocypher:
    def __init__(self):
        store    = wasmtime.Store()
        path     = importlib.resources.files("monocypher") / "monocypher.wasm"
        module   = wasmtime.Module.from_file(store.engine, path)
        instance = wasmtime.Instance(store, module, ())
        exports  = instance.exports(store)
        memory   = exports["memory"]
        self._read   = functools.partial(memory.read, store)
        self._write  = functools.partial(memory.write, store)
        self.__alloc = functools.partial(exports["bump_alloc"], store)
        self._reset  = functools.partial(exports["bump_reset"], store)
        self._lock   = functools.partial(exports["crypto_aead_lock"], store)
        self._unlock = functools.partial(exports["crypto_aead_unlock"], store)
        self._csprng = secrets.SystemRandom()

    def generate_key(self):
        return self._csprng.randbytes(32)

    def generate_nonce(self):
        return self._csprng.randbytes(24)

    def _alloc(self, n):
        return self.__alloc(n) & 0xffffffff

    def aead_lock(self, text, key, ad = b""):
        assert len(key) == 32
        try:
            macptr   = self._alloc(16)
            keyptr   = self._alloc(32)
            nonceptr = self._alloc(24)
            adptr    = self._alloc(len(ad))
            textptr  = self._alloc(len(text))

            self._write(key, keyptr)
            nonce = self.generate_nonce()
            self._write(nonce, nonceptr)
            self._write(ad,    adptr)
            self._write(text,  textptr)

            self._lock(
                textptr,
                macptr,
                keyptr,
                nonceptr,
                adptr, len(ad),
                textptr, len(text),
            )
            return (
                self._read(macptr, macptr+16),
                nonce,
                self._read(textptr, textptr+len(text)),
            )
        finally:
            self._reset()

    def aead_unlock(self, text, mac, key, nonce, ad = b""):
        assert len(mac) == 16
        assert len(key) == 32
        assert len(nonce) == 24
        try:
            macptr   = self._alloc(16)
            keyptr   = self._alloc(32)
            nonceptr = self._alloc(24)
            adptr    = self._alloc(len(ad))
            textptr  = self._alloc(len(text))

            self._write(mac, macptr)
            self._write(key, keyptr)
            self._write(nonce, nonceptr)
            self._write(ad, adptr)
            self._write(text, textptr)

            if self._unlock(
                textptr,
                macptr,
                keyptr,
                nonceptr,
                adptr, len(ad),
                textptr, len(text),
            ):
                raise ValueError("AEAD mismatch")
            return self._read(textptr, textptr+len(text))
        finally:
            self._reset()

if __name__ == "__main__":
    mc = Monocypher()
    key = mc.generate_key()
    message = "Hello, π!"
    mac, nonce, encrypted = mc.aead_lock(message.encode(), key)
    print(f"{key=}\n{mac=}\n{nonce=}\n{encrypted=}")
    decrypted = mc.aead_unlock(encrypted, mac, key, nonce)
    print(decrypted.decode())
